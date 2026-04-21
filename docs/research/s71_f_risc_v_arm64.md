# Session 71 / Agent F — Porting ARCHIMATION to RISC-V and ARM64

**Date:** 2026-04-20
**Scope:** Architecture-portability audit of the ARCHIMATION stack (trust.ko, pe-loader, AI daemon, packaging) with an eye toward running on aarch64 and riscv64 hardware shipping in 2024-2026.

## TL;DR

- **trust.ko is arch-portable today.** Zero inline-asm blocks in all 22 kernel sources. Clean rebuild on aarch64/riscv64 is expected once DKMS picks the right headers; estimated porting effort < 1 day.
- **pe-loader is structurally tied to x86_64.** Deliberate machine-type gate at `pe_parser.c:157` rejects anything that is not PE_MACHINE_I386 or PE_MACHINE_AMD64. ARM64 (0xAA64) constant is defined but never accepted. There is one hand-written x86_64 assembly file (`abi_thunk.S`, 177 lines).
- **Running Windows ARM64 PE binaries** natively on aarch64 Linux is achievable with a new ARM64-ABI thunk path (~400-600 LOC of new asm + routing) and machine-gate expansion — but the DLL stubs all assume `ms_abi` (MSFT x64), so retargeting is more like ~4-6k LOC of audit than a one-day port.
- **Running x86_64 Windows PEs on aarch64 hosts** should go through **FEX-Emu** (fastest, active, AVX/AVX2 landed 2024-25) or Hangover (Wine-native), not a reinvention.
- **Priority recommendation:** AArch64 first (Apple Silicon, Snapdragon X, Ampere/Graviton — real user hardware today). RISC-V as experimental track (hardware still slow, ecosystem maturing). Keep x86_64 as tier-1.

---

## 1 — Codebase survey (ARCH sensitivity audit)

### 1.1 trust kernel module — CLEAN

Files surveyed: 22 `.c` sources in `trust/kernel/` (see [absolute path C:\Users\wilde\Downloads\arch-linux-with-full-ai-control\trust\kernel\](../../trust/kernel/)).

**Inline assembly survey** (`rdtsc|cpuid|rdmsr|wrmsr|__x86|__amd64__|__i386__|CONFIG_X86`): **zero matches**.
**Inline asm idiom survey** (`__asm__|asm volatile`): **zero matches**.

Assessment: trust.ko is pure-C on top of Linux's arch-portable kernel APIs (spinlocks, RCU, workqueues, mempool, uaccess). The 2026-03 commit `0408da8` and Session 37's `e2f4ed7` did not introduce architecture-specific code. DKMS will produce `trust.ko` on aarch64/riscv64 given proper kernel headers.

**Caveat:** The Session 67 memory entry notes "22 .c sources match Kbuild" after the S59 drift fix. PKGBUILD `arch=('x86_64')` in [packages/trust-dkms/PKGBUILD:8](../../packages/trust-dkms/PKGBUILD) must be widened to `arch=('x86_64' 'aarch64' 'riscv64')`. Same for trust-system, pe-compat-dkms, pe-loader, windows-services PKGBUILDs.

### 1.2 pe-loader — x86_64 only by design

**Machine gate** ([pe-loader/loader/pe_parser.c:156-162](../../pe-loader/loader/pe_parser.c)):
```c
/* Validate machine type */
if (image->file_header.machine != PE_MACHINE_AMD64 &&
    image->file_header.machine != PE_MACHINE_I386) {
    fprintf(stderr, LOG_PREFIX "Unsupported machine type: 0x%04X\n",
            image->file_header.machine);
    goto fail;
}
```
PE_MACHINE_ARM64 (`0xAA64`) is defined in [pe_types.h:16](../../pe-loader/include/pe/pe_types.h) and referenced by `machine_name()` in [pe_diag.c:195](../../pe-loader/loader/pe_diag.c) — the loader can *identify* ARM64 binaries today, it just refuses to load them.

**Hand-written x86_64 assembly:** one file, [pe-loader/loader/abi_thunk.S](../../pe-loader/loader/abi_thunk.S), 177 lines of `.intel_syntax noprefix`. Implements the SysV ↔ ms_abi bridge (Windows x64 uses RCX/RDX/R8/R9 + 32-byte shadow stack; Linux uses RDI/RSI/RDX/RCX/R8/R9). This entire file has no AArch64 or RISC-V equivalent.

**ms_abi usage:** 494 occurrences of `__builtin_ms_va_list|ms_abi|__attribute__((ms_abi))` across 20+ DLL-stub files. Every COM vtable, every CRT wrapper, every PE entry-point call site assumes "Windows x64 caller convention is different from the host SysV caller convention and we need a thunk." On AArch64, AAPCS64 is the host convention AND Windows-ARM64 uses a slightly different variant of AAPCS64 (with different varargs and SEH rules) — so the whole ms_abi scaffold would need a parallel "arm64_ms_abi" track.

**SIMD/SSE/AVX intrinsics:** zero matches for `SIMD|SSE|AVX|_mm_|__m128|_mm256`. Good — no hand-rolled SSE paths to port.

**SIGILL trampoline:** [pe-loader/loader/sigill_trampoline.c](../../pe-loader/loader/sigill_trampoline.c) exists for catching unsupported x86 instructions. On AArch64 the set of "illegal" instructions is totally different, but the mechanism (signal handler + skip) is portable.

### 1.3 Packaging — arch field audit

From the grep above on `packages/*/PKGBUILD`:

| Package | Current `arch=()` | Needs change? |
|---|---|---|
| ai-control-daemon | `'any'` | no (pure Python) |
| ai-firewall | `'any'` | no |
| ai-first-boot-wizard | `'any'` | no |
| ai-desktop-config | `'any'` | no |
| pe-loader | `'x86_64'` | **add `'aarch64'` when ready** |
| trust-dkms | `'x86_64'` | **add `'aarch64' 'riscv64'`** |
| trust-system | `'x86_64'` | **add `'aarch64' 'riscv64'`** |
| pe-compat-dkms | `'x86_64'` | add `'aarch64'` (binfmt_pe works) |
| windows-services | `'x86_64'` | conditional (depends on PE) |

The profile (`profile/profiledef.sh:14`) hard-codes `arch="x86_64"`; mkarchiso only supports one target per build, so we would produce `archimation-2026.xx.xx-aarch64.iso` as a parallel artifact.

---

## 2 — RISC-V hardware landscape (2024-2026)

| Board | SoC / Cores | RVA profile | RVV 1.0 | Clock | RAM | Price | Notes |
|---|---|---|---|---|---|---|---|
| **SiFive HiFive Premier P550** | ESWIN EIC7700X / 4× SiFive P550 | RV64GBC (OoO) | no | 1.4 GHz | 16/32 GB LPDDR5 | $399-499 | First OoO RISC-V dev board. Faster than Unmatched, sometimes faster than RPi 4. Linpack 0.8 Gflops/W — still weak. |
| **BananaPi BPI-F3 / Milk-V Jupiter** | SpacemiT K1/M1 / 8× X60 | **RVA22** | **256-bit RVV 1.0** | ~1.6 GHz | 2/4/8/16 GB | $60 (Jupiter 4 GB) — $115 (M1 16 GB) | First commercial RVA22 + RVV 1.0 silicon. 2 TOPS NPU, 50 KDMIPS. Single-core ~30% ahead of Cortex-A55. |
| **StarFive VisionFive 2** (JH7110) | 4× SiFive U74 | RV64GC | no | 1.5 GHz | 2/4/8 GB | ~$100 | Roughly a Raspberry Pi 3 B+. Upstream kernel support is solid as of 2025 (Ubuntu 24.04 works). |
| **Milk-V Oasis** | Sophgo SG2380 / 16× SiFive P670 | RVA22 + V + B | yes | ~2 GHz+ | up to 64 GB LPDDR5 | ~$150 (pre-order $120) | 20 TOPS NPU. Slipped from Q3 2024; availability still TBD as of 2026. First "desktop-class" RISC-V. |
| **Ventana Veyron V1** | up to 16 cores per chiplet | server class | yes | 3.6 GHz | DDR5 | server-only | TSMC 5 nm. V1 sampling 2023-H2. V2 targeted Q3 2024 production. Up to 192 cores in cluster. |
| **AWS Graviton5** | 192 Neoverse (AArch64) | — | — | — | — | cloud | *Not RISC-V but listed: announced Dec 2025, 192 cores.* |

**Kernel / toolchain state (early 2026):**

- **Linux mainline:** RV64 well-supported. Ongoing CVE fixes (e.g. CVE-2025-40079 — RISC-V BPF sign-extension bug fixed upstream). Many boards ship DTS in-tree but USB/PCIe/GPU blocks are still out-of-tree.
- **LLVM 20 / GCC 14:** both ship RVV 1.0 codegen. Igalia's 2025 RISE project delivered +15-16 % on SPEC CPU 2017 via LLVM optimisations.
- **BPF/eBPF:** functional but arch-specific JIT still trailing x86_64 — the spec is the same, the behaviour isn't. Not in our critical path (trust kernel does no BPF).
- **Arch Linux RISC-V** ([archriscv.felixc.at](https://archriscv.felixc.at/)): unofficial port on RV64GC/lp64d. 243/264 core+extra packages current (92 %), 10072/13220 extra (76 %). Test boards listed: VisionFive 1, Unmatched, Milk-V Pioneer, LicheePi 4A.

**Verdict for ARCHIMATION on RISC-V:** Jupiter/BPI-F3 is the cheapest entry, Oasis is the interesting target (16-core desktop class), Veyron V2 is the only thing that could plausibly run the full AI cortex + PE loader workload. All of them are slower than a 2018-era x86_64 laptop. RISC-V is an **experimental track** for this project in 2026.

---

## 3 — ARM64 hardware landscape

| Class | Example | CPU | Notes |
|---|---|---|---|
| **Apple Silicon** | M1/M2/M3 (production), M4 WIP | Apple custom | Asahi Linux: M1/M2 production-ready; M4 **blocked on Apple's SPTM (Secure Page Table Monitor)**, Sven Peter calls it "rather painful" (as of Dec 2025). M4 will likely lag into 2026-H2. |
| **Snapdragon X Elite** | Qualcomm 12-core Oryon | Armv8/v9 | Linaro + TUXEDO shipped a proto laptop; Linux 6.15 covers many models; **Phoronix EOY-2025: performance regressions vs earlier testing, similar to 5-year-old Tiger Lake**. TUXEDO paused X1E Linux laptop. Ubuntu 25.04 + Fedora working on it. |
| **AWS Graviton4** | 96 Neoverse-V2 per socket | Armv9.0-A | Mature. 2-socket = 192 cores, 24 DDR channels. Crushes AmpereOne on memory-bandwidth benchmarks (3-4×). |
| **Graviton5** | Announced Dec 2025 | — | 192 cores/chip. |
| **Ampere Altra / Altra Max** | up to 128 Neoverse-N1 | Armv8.2 | Widely available. Stable. |
| **AmpereOne** | up to 192 cores | custom | 8 DDR channels (disadvantage). M variant with 12 channels targeted Q4 2025. MX with 256 cores "next year". |
| **Raspberry Pi 5** | 4× Cortex-A76 | Armv8.2 | Not serious for this project but very common. Arch Linux ARM ships `linux-rpi5`. |

**Distro state:**
- **Arch Linux ARM** (ALARM) — mirrors stalled around 2024-12-22 per a forum thread (Python rebuild); no official ETA. Packages still shipping but behind.
- **Arch Linux Ports** (ports.archlinux.page/aarch64) — unofficial, tracks Arch proper. Most core+extra packages build unmodified. AWS images every ~15 days (eu-central-1).

**Verdict for ARCHIMATION on AArch64:** this is where real user demand lives in 2026. Snapdragon X laptops (imperfect but shipping), Apple Silicon (if users tolerate Asahi), cloud on Graviton/Ampere. Tier-1 port target.

---

## 4 — Can we run Windows ARM64 PE binaries?

### 4.1 Current blocker
The parser-level rejection at `pe_parser.c:157-158` is cosmetic and can be lifted to accept `PE_MACHINE_ARM64` — but the entire ms_abi thunk chain is SysV↔Windows-x64 only.

### 4.2 What an ARM64-PE port requires

- **New assembly file:** `abi_thunk_arm64.S` implementing AAPCS64-Linux ↔ AAPCS64-Windows bridging. On both sides args are in X0-X7 and V0-V7, which *mostly* coincides, but:
  - Windows-ARM64 has different varargs conventions (ABI divergence documented by MSFT).
  - SEH unwinding differs (PData/XData tables vs Linux DWARF).
  - FP control registers (FPCR) behave differently.
  - Estimated 400-600 LOC, analogue to the existing 177-line `abi_thunk.S`.
- **Relocator updates** ([pe-loader/loader/pe_reloc.c](../../pe-loader/loader/pe_reloc.c)): add IMAGE_REL_ARM64_BRANCH26, ADDR32NB, ADDR64, PAGEBASE_REL21, REL21, PAGEOFFSET_12L/_12A relocation types (~8 new types). Estimated 200 LOC.
- **SEH host:** [pe-loader/loader/pe_exception.c](../../pe-loader/loader/pe_exception.c) implements x86_64 UWOP codes (UWOP_PUSH_MACHFRAME etc.). ARM64 SEH uses a totally different compact encoding. Roughly a parallel 600-800 LOC exception-unwind track.
- **DLL stubs:** 37+ `.so` files under `pe-loader/dlls/`. Most are pure-C and port automatically once ms_abi is replaced with the ARM64 variant. COM vtables need an ARM64 function-pointer attribute path. Estimated 1000-1500 LOC of careful edits across 40+ files.
- **Machine-gate:** 10-line edit at `pe_parser.c:157` and a new error path for mixed-architecture imports.

**Total LOC estimate for native Windows-ARM64 PE loading: ~3-5k LOC across ~50 files, ~4-6 week-engineer.**

### 4.3 Why bother? Windows-ARM64 native apps exist
Microsoft ships the whole Win32 surface in ARM64. Key apps with ARM64 native builds: Office, Chrome, VS Code, Firefox, Photoshop, Teams, Visual Studio 2022, .NET 8+. For a user on a Snapdragon X or Apple Silicon Mac, this is the fast path.

---

## 5 — Running x86_64 PEs on non-x86_64 hosts (emulation/translation)

This is the "user has an M4 MacBook, wants to run an x86 Windows .exe" case. Three viable paths:

### 5.1 FEX-Emu (preferred)
User-mode x86 + x86_64 emulator for AArch64 Linux. Active upstream. Supports AVX/AVX2 (recent). Can forward OpenGL/Vulkan calls to host libs to kill emulation overhead on GPU. Used in CrossOver ARM64.
- **Integration path:** if `file_header.machine == AMD64` and host is aarch64, shell out to FEX. Similar to how binfmt_misc already dispatches. ~150 LOC wrapper + a pe-compat-launcher mode.

### 5.2 Box64
Mature, Wine-friendly, widely-used on Raspberry Pi / Ampere boxes. Heavy reliance on library wrapping (libc/libdl/malloc redirection). Rosetta2 is 71 % native on 7zip, Box64 is 57 % per the Box86 blog. Simpler but slower than FEX for games.

### 5.3 Hangover (Wine-native approach)
Pairs Wine with FEX-Emu or Box64, keeps Wine on aarch64 native but emulates only the x86 app itself. [Hangover 11.0 released January 2026](https://github.com/AndreRH/hangover). Debian 11-13, Ubuntu 20.04-25.10 prebuilts.

### 5.4 Microsoft Prism (reference, not integrable)
Windows-on-ARM only, x86-64 → ARM64, tuned for Snapdragon X Elite, AVX/AVX2/BMI/FMA/F16C added 2024-25. Claims ≈ Rosetta 2 parity. Closed source — useful as a **benchmark target**, not as a component.

### 5.5 Apple Rosetta 2 (reference, deprecating)
x86_64 Mach-O → ARM64. Available inside Linux VMs (Parallels, UTM, Docker-Desktop). **Apple announced at WWDC 2025 that Rosetta 2 will be removed in macOS 28 (2027)**, limited to unmaintained games only — so any design predicated on Rosetta-in-Linux-VM has a ~2 year shelf life.

### 5.6 LOC estimate for a "box64 fallback" integration
- New file `pe-loader/loader/pe_foreign_arch.c` (~300 LOC) that detects arch mismatch at `pe_parse_file()` time and execs FEX/box64 with appropriate env.
- Package additions in profile/packages.x86_64 (mirrored to packages.aarch64) — `fex-emu` or `box64` + friends.
- Config flag `PE_ALLOW_FOREIGN_ARCH=1` gated behind trust, default off.
- **Total: ~500 LOC + packaging changes.**

---

## 6 — Old / edge hardware

**ARMv7 32-bit** (RPi 2/3, Allwinner boards 2014-2017): out of scope. The AI daemon needs FastAPI + optional llama-cpp + 2+ GB RAM; the PE loader wants 64-bit virtual addresses for image-base randomisation; trust kernel uses 64-bit atomics. 32-bit ARM is not a productive target.

**32-bit x86** (IA-32 only hosts): same argument. Already rejected architecturally.

---

## 7 — Porting LOC summary

| Piece | x86_64 LOC today | Port effort aarch64 | Port effort riscv64 |
|---|---|---|---|
| trust.ko + trust.h (22 files) | ~15k | < 500 LOC (PKGBUILD + CI + one audit pass) | same as aarch64 |
| PE loader core | ~16k | + 3-5k LOC (thunk/reloc/SEH) | experimental; Windows has no RV64 PE ecosystem — skip native |
| DLL stubs | ~65k | edit-pass ~1-1.5k LOC (ms_abi → arm64 variant); compile-clean the rest | skip native; use emulation |
| FEX/box64 integration | 0 | ~500 LOC + packaging | ~500 LOC + packaging |
| AI daemon + cortex | ~10k Python | **0** (pure Python/FastAPI) | 0 |
| Archiso profile | ~300 lines | ~50 LOC (new `profile-aarch64/` with `arch="aarch64"`, kernel pkg swap) | duplicate for riscv64 |
| PKGBUILDs | 9 files | trivial — widen `arch=(...)` | same |

**Grand total for a clean aarch64 port:** ~5-7k LOC + packaging + one engineer-month of audit/test.
**RISC-V port:** ~1-2k LOC (daemon + trust + packaging only), no native PE. Emulation via FEX unlikely to beat current RISC-V silicon — stick to AI daemon + trust on RV64.

---

## 8 — Recommendation

**Tier 1 (ship):** x86_64. Status quo. This is where the corpus lives.

**Tier 2 (next 6 months):** AArch64.
- Phase A — AI daemon + trust.ko rebuild + archiso-aarch64 profile. Userspace Windows PE **delegated to Hangover/FEX**. Ship ISO, accept "native-only Windows-ARM64 PEs not yet supported."
- Phase B — Windows-ARM64 native PE (new thunk + reloc + SEH). This is what differentiates us from "just run Wine."

**Tier 3 (research):** RISC-V (RV64GC + RVA22 baseline).
- AI daemon + trust.ko + archiso-riscv64 profile. Do not attempt PE loader — Microsoft does not ship Windows PE binaries for RV64. Use RISC-V purely as a "trust kernel + AI cortex on RV silicon" testbed on Jupiter/Oasis.

**Why AArch64 first and not RISC-V:**
1. Real users have AArch64 hardware today (Macs, Snapdragon X laptops, phones, most cloud).
2. Windows-ARM64 has a real native app ecosystem worth loading.
3. Emulation story (FEX/Box64/Hangover) is mature on aarch64, sketchy on riscv64.
4. Asahi, Fedora, Ubuntu, Arch Linux ARM all provide a runway.
5. RISC-V silicon in 2026 is still ~Pi-class for consumer boards; doesn't benefit from the loader's perf work.

**Pitfalls to expect:**
- Asahi's M4 block (Apple SPTM at GL2) means we cannot promise M4 coverage until Asahi unblocks, which may be late 2026 or 2027.
- Snapdragon X Linux performance regressed late 2025 per Phoronix EOY — don't promise parity with Windows-on-ARM until kernel 6.16+ stabilises.
- Rosetta 2 removal in macOS 28 invalidates any x86-under-Rosetta-in-VM plan.
- RISC-V mainline BPF still has arch-specific bugs (CVE-2025-40079 class); keep eBPF off the critical path.
- `arch=('any')` PKGBUILDs (4 of 9) already portable — focus audit time on the 5 binary ones.

---

## Sources

**Codebase references:**
- [pe-loader/loader/pe_parser.c](../../pe-loader/loader/pe_parser.c) (349 lines; machine gate at 156-162)
- [pe-loader/loader/pe_diag.c](../../pe-loader/loader/pe_diag.c) (523 lines; machine_name at 189-198)
- [pe-loader/loader/abi_thunk.S](../../pe-loader/loader/abi_thunk.S) (177 lines; only x86 asm in tree)
- [pe-loader/include/pe/pe_types.h](../../pe-loader/include/pe/pe_types.h) (ARM64 constant 0xAA64 defined at line 16)
- trust/kernel/*.c (22 files, zero inline asm)
- Recent commits: e2f4ed7 (S37 bug hunt), 73097a8 (S36), 20a8f86 (S30 perf), 0408da8 (initial)

**External (RISC-V):**
- [Phoronix: SiFive HiFive Premier P550 RISC-V Linux Performance Review](https://www.phoronix.com/review/sifive-hifive-premier-p550/7)
- [Jeff Geerling: SiFive HiFive Premier P550](https://www.jeffgeerling.com/blog/2025/sifives-hifive-premier-p550-strange-powerful-risc-v-board/)
- [SiFive HiFive Premier P550 product page](https://www.sifive.com/boards/hifive-premier-p550)
- [CNX-Software: Banana Pi BPI-F3 with SpacemiT K1 octa-core RISC-V AI SoC](https://www.cnx-software.com/2024/05/10/banana-pi-bpi-f3-sbc-spacemit-k1-octa-core-risc-v-ai-soc/)
- [Milk-V Jupiter product page](https://milkv.io/jupiter)
- [Hackster.io: Milk-V Oasis 16-core RISC-V board](https://www.hackster.io/news/milk-v-goes-after-llms-on-the-desktop-with-its-powerful-16-core-risc-v-oasis-motherboard-97378066ac79)
- [The Next Platform: Ventana Veyron V2](https://www.nextplatform.com/2023/11/07/ventana-launches-veyron-v2-risc-v-into-the-datacenter/)
- [StarFive VisionFive 2 Phoronix benchmarks](https://www.phoronix.com/review/visionfive2-riscv-benchmarks)
- [Igalia: LLVM RISC-V RVV optimisation case study](https://blogs.igalia.com/compilers/2025/11/22/unlocking-15-16-more-performance-a-case-study-in-llvm-optimization-for-risc-v/)
- [LLVM docs: RISC-V Vector Extension](https://llvm.org/docs/RISCV/RISCVVectorExtension.html)
- [Arch Linux RISC-V tracker](https://archriscv.felixc.at/)
- [RISC-V International: Full-Fat, Kernel-Ready upstreaming](https://riscv.org/blog/risc-v-upstreaming/)
- [Windows Forum: CVE-2025-40079 RISC-V BPF sign-extension fix](https://windowsforum.com/threads/linux-kernel-patch-fixes-risc-v-bpf-sign-extension-for-cve-2025-40079.387022/)

**External (ARM64):**
- [Phoronix: Snapdragon X Elite Linux EOY 2025](https://www.phoronix.com/review/snapdragon-x-elite-linux-eoy2025)
- [Linaro blog: Linux on Snapdragon X Elite](https://www.linaro.org/blog/linux-on-snapdragon-x-elite/)
- [MS Learn: How emulation works on Arm (Prism)](https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation)
- [MS TechCommunity: Prism x86 update AVX/AVX2](https://techcommunity.microsoft.com/blog/windowsosplatform/windows-on-arm-runs-more-apps-and-games-with-new-prism-update/4475631)
- [Phoronix: Asahi Linux EOY 2025 CCC (M3/M4/M5 bring-up)](https://www.phoronix.com/news/Asahi-Linux-EOY-2025-CCC)
- [AppleInsider: Asahi Linux M4 roadblock (SPTM)](https://appleinsider.com/articles/25/04/08/asahi-linux-m4-support-hits-a-roadblock-because-of-apple-silicon-changes)
- [Asahi Linux M4 feature-support page](https://asahilinux.org/docs/platform/feature-support/m4/)
- [Phoronix: AmpereOne vs Graviton4 benchmarks](https://www.phoronix.com/review/ampereone-aws-graviton4)
- [Arch Linux ARM](https://archlinuxarm.org/)
- [Arch Linux Ports AArch64](https://ports.archlinux.page/aarch64/)

**External (emulation / translation):**
- [Box86/Box64 vs QEMU vs FEX vs Rosetta2](https://box86.org/2022/03/box86-box64-vs-qemu-vs-fex-vs-rosetta2/)
- [FEX-Emu homepage](https://fex-emu.com/)
- [FEX-Emu GitHub](https://github.com/FEX-Emu/FEX)
- [Box64 GitHub (ptitSeb)](https://github.com/ptitSeb/box64)
- [Hangover GitHub (AndreRH)](https://github.com/AndreRH/hangover)
- [Phoronix: Hangover 0.8.3](https://www.phoronix.com/news/Hangover-0.8.3)
- [Apple Developer: Running Intel Binaries in Linux VMs with Rosetta](https://developer.apple.com/documentation/virtualization/running-intel-binaries-in-linux-vms-with-rosetta)
- [MacRumors: Rosetta 2 removal in macOS 28 (2027)](https://forums.macrumors.com/threads/no-rosetta-2-from-macos-28-how-it-will-affect-docker-utm-whisky-wine-etc.2458776/)

---

## Appendix — 400-word executive summary (per brief)

ARCHIMATION today targets x86_64 exclusively. A codebase audit confirms the **trust kernel module is architecturally portable**: 22 `.c` sources, zero inline assembly, no x86-specific intrinsics. A ≤ 1-day PKGBUILD widening (adding `'aarch64'` and `'riscv64'` to five packages) plus a kernel-headers CI pass gets `trust.ko` building on both new architectures. trust-system, pe-compat-dkms, and windows-services need similar surgery.

The **PE loader is structurally x86_64-centric**. A deliberate machine-type gate at `pe_parser.c:157` rejects anything that is not `IMAGE_FILE_MACHINE_I386` or `IMAGE_FILE_MACHINE_AMD64`; the ARM64 constant (0xAA64) is already defined and surfaced in `pe_diag.c` but never accepted. The one hand-written x86_64 assembly file is `abi_thunk.S` (177 LOC), bridging SysV and Windows-x64 calling conventions. Across 20+ DLL stubs there are 494 usages of `ms_abi` / `__builtin_ms_va_list`, each of which would need a parallel ARM64 track. No SSE/AVX intrinsics exist in-tree — good.

A **native Windows-ARM64 PE load** path is estimated at ~3-5 k LOC: new `abi_thunk_arm64.S` (~400-600 LOC), ARM64 base relocation types (~200 LOC), ARM64 SEH / PData-XData unwind (~600-800 LOC), and an ms_abi→arm64-ms audit pass across 40+ files (~1-1.5 k LOC). Payoff: Office, Chrome, VS Code, Photoshop, .NET 8+ all ship ARM64 native today.

For **x86 PEs on non-x86 hosts**, the right answer is not to reinvent: integrate **FEX-Emu** (active, AVX/AVX2 landed 2024-25, CrossOver uses it) or **Hangover 11.0** (Wine-native, Jan 2026). Rosetta 2 is off-limits strategically — Apple removes it in macOS 28 (2027). Microsoft Prism is closed source.

**Hardware reality check:** RISC-V consumer boards in 2026 (P550 at $399, Jupiter at $60-115, Oasis at ~$150, VisionFive 2 at $100) are roughly Pi-3 to Pi-4 class; Ventana Veyron V2 is server-only. AArch64 is where users are — Apple Silicon (M1/M2 solid, M4 still Asahi-blocked), Snapdragon X (shipping but regressing per Phoronix EOY 2025), Ampere/Graviton (cloud). Arch Linux ARM is slow but functioning; Arch Linux Ports aarch64 is more current.

**Recommendation:** Tier 1 keep x86_64. Tier 2 port AArch64 first — userspace emulation via FEX in phase A, native Windows-ARM64 PE support in phase B. Tier 3 RISC-V as experimental "trust + AI daemon on RV64" only; skip native PE because Microsoft ships no RV64 PE ecosystem. Widen `arch=()` fields on packages immediately; defer assembly work until a concrete aarch64 test rig exists.
