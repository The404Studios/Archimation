# S71-H — Modern Kernel & Module Hardening (2024–2026)

**Project:** ARCHWINDOWS — trust.ko + wdm_host.ko DKMS modules
**Research angle:** LLVM-CFI, LTO, shadow call stack, KASLR/FG-KASLR, STRUCTLEAK, KMSAN, FORTIFY_SOURCE,
HARDENED_USERCOPY, SLAB_FREELIST_HARDENED — what to turn on for pkg-25, what breaks trust.ko.
**Date:** 2026-04-20
**Current state files surveyed:**
- `trust/kernel/Kbuild` (22 .c files; ccflags-y = include paths only — no hardening flags)
- `packages/trust-dkms/PKGBUILD` (pkgrel 7; hook triggers on `linux`, `linux-lts`, `linux-hardened`, `linux-zen`)
- `profile/packages.x86_64` (ships `linux` + `linux-headers` only; no `linux-hardened`)

---

## 1. Hardening Matrix 2026

| Feature | Kconfig | Status (mainline) | Arch `linux` default | `linux-hardened` | Runtime cost (modern CPU) | Runtime cost (pre-SMEP, ≤Ivy Bridge) | trust.ko impact |
|---|---|---|---|---|---|---|---|
| **LLVM-CFI (kCFI)** | `CFI_CLANG` | x86_64 since 6.1 (Sami Tolvanen) | **OFF** (GCC build) | **OFF** | ~1% (Android data; [source](https://lwn.net/Articles/869267/)) | ~2–5% (more indirect-branch pressure) | Requires Clang build of module + matching CFI hashes; GCC-built DKMS module will **fail to load** into CFI kernel |
| **ThinLTO** | `LTO_CLANG_THIN` | x86_64 stable since 5.12 | OFF | OFF | Runtime +0–2%; build +30–60% | Runtime +0–2% | Module must be Clang-ThinLTO-built; GCC module loads fine but misses cross-TU devirt |
| **Full LTO** | `LTO_CLANG_FULL` | x86_64 stable since 5.12 | OFF | OFF | Runtime +0–3%; **build 3–8× slower, 8–16 GB RAM peak** | Same | **Historically breaks BTF** (pahole <1.27); fixed in pahole 1.27 (June 2024) — still fragile for out-of-tree modules |
| **Shadow Call Stack** | `SHADOW_CALL_STACK` | **arm64 only** (Android) | N/A | N/A | — | — | Not applicable on x86_64; CET Shadow Stack is the x86 analog |
| **CET Shadow Stack (x86)** | `X86_USER_SHADOW_STACK` | userspace since 6.4; kernel shstk via `X86_KERNEL_IBT` 5.18 | **IBT ON**, user-shstk available | ON | ~0% (hardware-accelerated) | N/A — needs Tiger Lake/Zen 3 or newer | trust.ko must be IBT-clean (no speculative indirect calls without ENDBR) |
| **KASLR (base)** | `RANDOMIZE_BASE` | default since 3.14 | **ON** | ON | ~0% | ~0% | None |
| **FG-KASLR** | `FG_KASLR` | **NOT mainlined** (v10 stalled 2022) | OFF | OFF | ~1% + ~1 s boot | Same | Would require rebuild coupling; skip |
| **STRUCTLEAK** | `GCC_PLUGIN_STRUCTLEAK_BYREF_ALL` | GCC-plugin since 4.11 | ON (legacy) | ON | ~1% | ~1% | Superseded on GCC 12+/Clang by `INIT_ON_ALLOC_DEFAULT_ON` |
| **STACKLEAK** | `GCC_PLUGIN_STACKLEAK` | GCC-plugin since 4.20 | OFF | **ON** | ~1–2% syscall exit | ~2–3% | None — trust.ko uses syscall path but cost is in exit trampoline |
| **INIT_ON_ALLOC** | `INIT_ON_ALLOC_DEFAULT_ON` | since 5.3 | ON (Arch enables) | ON | ~1% alloc-heavy paths | ~2% | None |
| **INIT_ON_FREE** | `INIT_ON_FREE_DEFAULT_ON` | since 5.3 | OFF | ON | ~2–3% | ~3–5% | None |
| **FORTIFY_SOURCE** | `FORTIFY_SOURCE` | since 4.13; moved under `Kconfig.hardening` Jan 2025 | **ON** | ON | ~0% (compile-time) | ~0% | Module inherits: beware `memcpy`/`strcpy` with computed sizes — fortify may warn |
| **HARDENED_USERCOPY** | `HARDENED_USERCOPY` | since 4.8; defaulted OFF Jan 2025 | **ON** (Arch keeps enabled) | ON | 2–10% general; 2–14% netperf localhost | 4–15% | **Relevant**: `copy_to_user`/`copy_from_user` in `trust_syscall.c`, `trust_dispatch.c` — must pass size validation |
| **SLAB_FREELIST_HARDENED** | `SLAB_FREELIST_HARDENED` | since 4.14 | **ON** | ON | ~1% | ~1–2% | None |
| **SLAB_FREELIST_RANDOM** | `SLAB_FREELIST_RANDOM` | since 4.10 | ON | ON | <1% | <1% | None |
| **RANDOM_KMALLOC_CACHES** | `RANDOM_KMALLOC_CACHES` | since 6.6 | ON | ON | <1% | <1% | None — but interacts with cross-cache UAF (relevant to CVE-2024-1086 family) |
| **STACKPROTECTOR_STRONG** | `STACKPROTECTOR_STRONG` | since 3.14 | **ON** | ON | <1% | <1% | None |
| **STRICT_KERNEL_RWX** | `STRICT_KERNEL_RWX` | since 4.11 | ON | ON | ~0% | ~0% | trust.ko **cannot self-modify code** (it doesn't — but keep this invariant) |
| **LOCKDOWN_LSM** | `SECURITY_LOCKDOWN_LSM` | since 5.4 | ON (available, off at boot) | **ON + early + force confidentiality** | ~0% | ~0% | Under `integrity` mode, **unsigned DKMS modules refuse to load** |
| **MODULE_SIG_FORCE** | `MODULE_SIG_FORCE` | since 3.7 | OFF | **ON** (some builds) | ~0% | ~0% | DKMS must sign trust.ko + wdm_host.ko — currently **not wired** |
| **KPTI (Meltdown)** | `PAGE_TABLE_ISOLATION` | since 4.15 | ON (auto-detect) | ON | 0–800% syscall-heavy workloads on old CPUs without PCID | **Severe** (no PCID on pre-Haswell → full TLB flush per mode switch) | trust.ko syscall path pays KPTI cost per ioctl |
| **KMSAN** | `KMSAN` | since 6.1 | **OFF** (dev-tool only) | OFF | 3–5× slowdown | Same | Keep OFF in prod; useful for debugging trust.ko UAF during dev |

**Sources:** [LWN: x86 Clang CFI](https://lwn.net/Articles/869267/), [Android kCFI](https://source.android.com/docs/security/test/kcfi), [KSPP Recommended Settings](https://kspp.github.io/Recommended_Settings.html), [linux/kernel/configs/hardening.config](https://github.com/torvalds/linux/blob/master/kernel/configs/hardening.config), [Kernel docs: KMSAN](https://docs.kernel.org/dev-tools/kmsan.html), [Kernel docs: CET Shadow Stack](https://docs.kernel.org/next/x86/shstk.html), [LWN: FG-KASLR](https://lwn.net/Articles/824307/).

---

## 2. Arch `linux` vs `linux-hardened` — when to ship which

Arch's official `linux` (6.13 series Jan 2025) is built with GCC and ships the **mainline KSPP-friendly defaults**: KASLR, FORTIFY_SOURCE, HARDENED_USERCOPY, STACKPROTECTOR_STRONG, SLAB_FREELIST_HARDENED, STRICT_KERNEL_RWX, INIT_ON_ALLOC_DEFAULT_ON, KPTI. **Not enabled:** CFI_CLANG (GCC build), LTO, INIT_ON_FREE, STACKLEAK, MODULE_SIG_FORCE, early LOCKDOWN.

`linux-hardened` adds:
- `init_on_free=1` default
- STACKLEAK plugin
- `kptr_restrict=2` (masks kernel pointers in dmesg/procfs)
- `kexec_load_disabled=1`
- stronger user-ASLR (PaX-derived patches)
- LOCKDOWN LSM enabled early, `integrity` or `confidentiality` mode
- `/proc/$pid/maps` restrictions
- seccomp BPF defaults tightened

**When to ship `linux`:** default workstation / gaming / dev-loop ISO. Wine, Steam, DXVK all expect mainline behavior; lockdown interferes with `nvidia-utils` NVreg calls and some DKMS stacks.

**When to ship `linux-hardened`:** security-conscious deployment, non-gaming. Note that **lockdown `integrity` mode will break unsigned trust.ko DKMS build** unless we wire module signing into the DKMS hook (currently unwired — see §4).

**Sources:** [ArchWiki: Kernel](https://wiki.archlinux.org/title/Kernel), [Arch forum: linux vs hardened](https://bbs.archlinux.org/viewtopic.php?id=304476), [ArchWiki: Security](https://wiki.archlinux.org/title/Security).

---

## 3. Recommended Kernel Config for pkg-25

**Keep Arch `linux` as the shipped default kernel** (compatibility with Wine/Steam/NVIDIA/gaming is non-negotiable for ARCHWINDOWS' user-facing pitch). Do **not** ship a custom-compiled kernel — the maintenance cost is not justified and it breaks `pacman -Syu` expectations.

**Layered recommendation:**

1. **pkg-25 ships Arch `linux` (stock) — already carries CFI-equivalent mitigations via SMEP/SMAP/IBT/KPTI.** No kernel changes needed.
2. **Offer `linux-hardened` as an OPTIONAL kernel in `packages.x86_64`** — users can opt in via a post-install helper, same way NVIDIA is handled.
3. **Do NOT enable `LTO_CLANG_FULL`** even if we ever ship a custom kernel: BTF under full LTO is still brittle in 2026 despite pahole 1.27 fixes; eBPF tooling (which ARCHWINDOWS' AI cortex depends on for behavioral markov) will silently regress.
4. **If we ever custom-compile**, target `LTO_CLANG_THIN` + `CFI_CLANG` + `STACKLEAK` + `HARDENED_USERCOPY` + `FORTIFY_SOURCE` — this is the Android baseline and survives BTF generation.

**Explicit list for any custom build:**
```
CONFIG_CFI_CLANG=y
CONFIG_LTO_CLANG_THIN=y
CONFIG_GCC_PLUGIN_STACKLEAK=y     # still useful under Clang if plugin built
CONFIG_HARDENED_USERCOPY=y
CONFIG_FORTIFY_SOURCE=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
CONFIG_INIT_ON_FREE_DEFAULT_ON=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_RANDOM_KMALLOC_CACHES=y
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_STRICT_KERNEL_RWX=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
# DO NOT SET: CONFIG_LTO_CLANG_FULL=y    # BTF risk
# DO NOT SET: CONFIG_FG_KASLR=y          # not mainlined
# DO NOT SET: CONFIG_KMSAN=y             # dev-only, 3-5x slowdown
```

---

## 4. trust.ko Build Flags — Compatibility Matrix

**Current `trust/kernel/Kbuild`:**
```make
obj-m := trust.o
trust-objs := trust_core.o ...  # 22 files
ccflags-y := -I$(src)/../include -I$(src)/include
```

This is minimally specified: **no explicit hardening flags** — the module inherits everything from the host kernel's build system via `$(MAKE) -C $(KDIR) M=$(PWD)`.

**Compatibility outcomes:**

| Host kernel build | trust.ko DKMS build outcome | Notes |
|---|---|---|
| Arch `linux` (GCC) | ✅ Builds + loads cleanly today | Already verified S56-S67 |
| Arch `linux-hardened` (GCC + extra hardening) | ✅ Builds; ⚠️ loads **only** if unsigned modules allowed (lockdown off or `none`/`integrity`-with-module-signing-wired) | Module sig not wired in S59–S67 DKMS flow |
| Custom Clang + `CFI_CLANG=y` | ❌ **Will fail to load** — GCC-built module lacks kCFI hash symbols | Must rebuild module with Clang + matching config |
| Custom Clang + `LTO_CLANG_THIN=y` | ⚠️ Builds but misses cross-TU devirt benefit | Module gets no LTO; host kernel does. Safe combination |
| Custom Clang + `LTO_CLANG_FULL=y` + BTF | ⚠️ Risks pahole crash on older pahole | Needs pahole ≥1.27 (June 2024) — verify with `pahole --version` in build-packages.sh |

**Required additions to `trust/kernel/Kbuild` for future hardening compatibility** (not blocking pkg-25):

```make
# Silence FORTIFY_SOURCE warnings in trust_compat.c (computed sizes in memcpy)
ccflags-$(CONFIG_FORTIFY_SOURCE) += -Wno-array-bounds

# If the module is ever cross-built against a CFI kernel, we need Clang + matching flags.
# The existing Kbuild inherits host CC automatically, so no change needed — but we should
# document the CC=clang requirement in packages/trust-dkms/PKGBUILD.
```

**PKGBUILD changes needed for `linux-hardened` support** (low priority; S71 handoff):
```bash
# packages/trust-dkms/PKGBUILD — add optdepends
optdepends=('linux-hardened-headers: build against linux-hardened kernel')

# Wire module signing when lockdown=integrity is active:
# DKMS already supports --sign via MOK keys in /var/lib/dkms/mok.pub — verify at build time.
```

---

## 5. Old-Hardware Cost Table

Target: pre-2014 Intel (Ivy Bridge and older, no SMEP/SMAP/PCID) vs modern (Ice Lake+, full CET support).

| Feature | Ivy Bridge (2012) | Haswell (2013, SMAP+PCID) | Skylake (2015) | Tiger Lake+ (2020, CET) |
|---|---|---|---|---|
| KASLR | 0% | 0% | 0% | 0% |
| KPTI (syscall-heavy) | **30–800%** (no PCID!) | 5–30% | 2–15% | <2% |
| SMEP/SMAP software fallback | N/A (hardware absent → HW protection disabled) | full HW | full HW | full HW |
| CFI (Clang) | 2–5% | 1–3% | 1–2% | <1% |
| HARDENED_USERCOPY | 4–15% | 3–10% | 2–8% | 1–5% |
| INIT_ON_FREE | 3–5% | 2–4% | 2–3% | 1–2% |
| CET Shadow Stack | N/A | N/A | N/A | ~0% (HW) |
| LOCKDOWN (confidentiality) | 0% | 0% | 0% | 0% |

**Takeaway for ARCHWINDOWS users on old hardware (laptop + ThinkPad niche, which MEMORY.md shows we do target via tlp/acpid):** KPTI is the biggest cost on pre-Haswell. KSPP's full recommendation set is ~10–20% aggregate on Ivy Bridge vs ~2–4% on modern; acceptable for a security-focused ISO but measurable.

**Sources:** [Breaking Bits: SMEP](https://breaking-bits.gitbook.io/breaking-bits/exploit-development/linux-kernel-exploit-development/supervisor-mode-execution-protection-smep), [USENIX login: Kernel Isolation](https://www.usenix.org/system/files/login/articles/login_winter18_03_gruss.pdf), [Phoronix: Arch kernel perf](https://www.phoronix.com/review/arch-linux-kernels-2023).

---

## 6. 2024–2026 CVEs These Mitigations Address (cited)

| CVE | Class | Mitigation |
|---|---|---|
| **CVE-2024-1086** (nf_tables UAF, "Flipping Pages") | Slab UAF → LPE; actively exploited by RansomHub/Akira | `RANDOM_KMALLOC_CACHES` (6.6+) makes heap-spray unreliable; `CFI_CLANG` blocks the vtable-overwrite variant. [coffinsec analysis](https://pwning.tech/nftables/) |
| **CVE-2024-50264** (AF_VSOCK race) | Race → LPE via vsock double-free | `SLAB_FREELIST_HARDENED`, `INIT_ON_FREE`. [a13xp0p0v drill](https://a13xp0p0v.github.io/2025/09/02/kernel-hack-drill-and-CVE-2024-50264.html) |
| **CVE-2025-38352** (POSIX CPU timers UAF) | Race → LPE; PoC public Sep 2025 | `INIT_ON_FREE` + `SLAB_FREELIST_HARDENED`. [gbhackers](https://gbhackers.com/poc-exploit-released-for-use-after-free-vulnerability-in-linux-kernel/) |
| **CVE-2025-20741** (kernel alchemy series) | Generic UAF exploit primitives | `RANDOM_KMALLOC_CACHES`, `CFI_CLANG` (for vtable paths). [coffinsec](https://blog.coffinsec.com/0day/2026/04/02/kernel-alchemy-pt1.html) |
| **CVE-2018-9568** (original xor-freelist bypass) | Slab metadata overwrite | `SLAB_FREELIST_HARDENED` historical root. [KSPP study](https://samsung.github.io/kspp-study/heap-ovfl.html) |

**Sources:** [CIQ: 2025 kernel CVEs](https://ciq.com/blog/linux-kernel-cves-2025-what-security-leaders-need-to-know-to-prepare-for-2026/), [Linux Journal: 2025 breaches](https://www.linuxjournal.com/content/most-critical-linux-kernel-breaches-2025-so-far), [xairy exploitation collection](https://github.com/xairy/linux-kernel-exploitation).

---

## 7. BTF Compatibility Note (trust.ko is BTF-clean — keep it that way)

Our MEMORY.md notes repeatedly emphasize "BTF-clean build". This matters because:

- The AI cortex's `behavioral_markov.py` **reads kernel eBPF syscall traces** via BTF-relocatable CO-RE programs.
- pahole <1.27 **crashes** on modules built under `CONFIG_LTO_CLANG_FULL` (fixed June 2024 in [pahole 1.27](https://patchwork.kernel.org/project/netdevbpf/patch/ZnCWRMfRDMHqSxBb@x1/)).
- Fix in `scripts/build-packages.sh` verify stage: `pahole --version | awk '$2>=1.27'` before allowing DKMS hook install against any Clang+LTO kernel.
- ThinLTO + BTF works since pahole 1.27 and kernel 6.10+ (ref: [Linux-v6.9.7 BTF/ThinLTO thread](https://www.spinics.net/lists/bpf/msg119671.html)).

**Action for pkg-25:** add a `verify_btf_pahole_version()` check to `scripts/build-packages.sh`, analogous to the existing `verify_trust_dkms_manifest()` from S67.

---

## 8. Recommendation Summary

1. **Ship `linux` (stock Arch) as default in pkg-25.** Already carries 80% of KSPP recommendations. trust.ko builds and loads cleanly. No change required.
2. **Add `linux-hardened` + `linux-hardened-headers` to `packages.x86_64`** as an optional kernel. Do NOT make it default — it breaks Wine/NVIDIA/kernel-mode-driver flows.
3. **Wire DKMS module signing** into `packages/trust-dkms/trust-dkms.install` (MOK-based, documented in [ArchWiki Signed kernel modules](https://wiki.archlinux.org/title/Signed_kernel_modules)). This is the blocker for running trust.ko under lockdown=`integrity`.
4. **Add `verify_btf_pahole_version()` build-time guard** — protects the AI cortex's eBPF CO-RE path.
5. **Do not custom-compile a kernel.** The maintenance cost of a custom-built CFI/LTO kernel dwarfs the security delta on top of what `linux-hardened` already provides for opt-in users.
6. **Do not chase FG-KASLR** (not mainlined as of 2026-04, v10 stalled since 2022).
7. **Do not enable KMSAN in any shipped build** — dev-only.

---

## 400-Word Summary

ARCHWINDOWS pkg-25 should stick with the stock Arch `linux` kernel as default and **add `linux-hardened` as an optional kernel** in `packages.x86_64` for users who want the reduced attack surface. The stock kernel already ships the majority of KSPP-recommended mitigations (KASLR, FORTIFY_SOURCE, HARDENED_USERCOPY, SLAB_FREELIST_HARDENED, STACKPROTECTOR_STRONG, STRICT_KERNEL_RWX, INIT_ON_ALLOC_DEFAULT_ON, KPTI auto-detect, random kmalloc caches). `linux-hardened` layers on STACKLEAK, `init_on_free=1`, `kptr_restrict=2`, disabled kexec, and early LOCKDOWN, at a cost of ~3–5% on modern CPUs and ~10–20% aggregate on pre-Haswell hardware (where KPTI without PCID dominates). **CFI_CLANG is not worth custom-compiling for** — the compatibility cost (Clang everywhere, matching CFI hashes between kernel and every DKMS module including trust.ko and wdm_host.ko) exceeds the ~1% security delta on top of SMEP/SMAP/IBT which are already enabled. **ThinLTO is viable but not critical**; Full LTO is not recommended because BTF generation under pahole <1.27 crashes (fixed June 2024 per [pahole 1.27 announce](https://patchwork.kernel.org/project/netdevbpf/patch/ZnCWRMfRDMHqSxBb@x1/)), and our AI cortex's behavioral markov path depends on eBPF CO-RE. **FG-KASLR has been out-of-tree since 2020 and v10 stalled in 2022** — skip. **KMSAN is dev-only** (3–5× slowdown per [docs.kernel.org](https://docs.kernel.org/dev-tools/kmsan.html)) — useful when chasing trust.ko UAFs, never in a shipped ISO. The CVEs that motivate this hardening (CVE-2024-1086 nf_tables "Flipping Pages", CVE-2024-50264 AF_VSOCK, CVE-2025-38352 POSIX CPU timers, CVE-2025-20741 kernel alchemy) are collectively mitigated by `RANDOM_KMALLOC_CACHES` (6.6+), `SLAB_FREELIST_HARDENED`, and `INIT_ON_FREE` — all already present in `linux-hardened`. The real blocker for shipping `linux-hardened` is **DKMS module signing**: lockdown=`integrity` refuses unsigned modules, and our current `packages/trust-dkms/PKGBUILD` does not wire MOK-based signing into the DKMS hook. Wire `dkms --sign` with a generated MOK key at first boot (via `ai-first-boot-wizard`) and `linux-hardened` becomes a drop-in alternative for security-conscious users without touching `trust/kernel/Kbuild`. Add `verify_btf_pahole_version()` to `scripts/build-packages.sh` (analogous to S67's `verify_trust_dkms_manifest()`) so we fail at build time if pahole <1.27 ever slips in — the AI cortex's eBPF path depends on it, and silent BTF regression is the failure mode MEMORY.md has previously called out.

---

## Citations / Kernel commits / LWN articles

- [LWN: x86 Clang CFI](https://lwn.net/Articles/869267/) — Sami Tolvanen CFI patchset for x86_64
- [LKML: v3 x86 Clang CFI patchset](https://lkml.kernel.org/lkml/20210914191045.2234020-1-samitolvanen@google.com/)
- [LWN: Function Granular KASLR](https://lwn.net/Articles/824307/)
- [Phoronix: FGKASLR v6 revived](https://www.phoronix.com/news/FGKASLR-v6-Linux)
- [LKML: v10 FG-KASLR (last posting)](https://lore.kernel.org/lkml/20220209185752.1226407-1-alexandr.lobakin@intel.com/)
- [Kernel docs: CET Shadow Stack](https://docs.kernel.org/next/x86/shstk.html)
- [Phoronix: Intel CET SS in 6.4](https://www.phoronix.com/news/Linux-6.4-Shadow-Stack-Coming)
- [Kernel docs: KMSAN](https://docs.kernel.org/dev-tools/kmsan.html)
- [Google KMSAN repo](https://github.com/google/kmsan)
- [LKML: pahole 1.27 announce + ThinLTO fixes](https://patchwork.kernel.org/project/netdevbpf/patch/ZnCWRMfRDMHqSxBb@x1/)
- [BPF mailing list: v6.9.7 BTF/ThinLTO](https://www.spinics.net/lists/bpf/msg119671.html)
- [KSPP Recommended Settings](https://kspp.github.io/Recommended_Settings.html)
- [linux/kernel/configs/hardening.config](https://github.com/torvalds/linux/blob/master/kernel/configs/hardening.config)
- [linux/security/Kconfig.hardening](https://github.com/torvalds/linux/blob/master/security/Kconfig.hardening)
- [kernel-hardening-checker (a13xp0p0v)](https://github.com/a13xp0p0v/kernel-hardening-checker)
- [ArchWiki: Kernel](https://wiki.archlinux.org/title/Kernel)
- [ArchWiki: Security](https://wiki.archlinux.org/title/Security)
- [ArchWiki: Signed kernel modules](https://wiki.archlinux.org/title/Signed_kernel_modules)
- [ArchWiki: Dynamic Kernel Module Support](https://wiki.archlinux.org/title/Dynamic_Kernel_Module_Support)
- [Arch forum: linux vs linux-hardened vs linux-lts](https://bbs.archlinux.org/viewtopic.php?id=304476)
- [Phoronix: Arch kernel flavors perf](https://www.phoronix.com/review/arch-linux-kernels-2023)
- [CIQ: 2025 kernel CVEs](https://ciq.com/blog/linux-kernel-cves-2025-what-security-leaders-need-to-know-to-prepare-for-2026/)
- [Linux Journal: 2025 breaches](https://www.linuxjournal.com/content/most-critical-linux-kernel-breaches-2025-so-far)
- [coffinsec: CVE-2025-20741 analysis](https://blog.coffinsec.com/0day/2026/04/02/kernel-alchemy-pt1.html)
- [pwning.tech: CVE-2024-1086 Flipping Pages](https://pwning.tech/nftables/)
- [a13xp0p0v: CVE-2024-50264 drill](https://a13xp0p0v.github.io/2025/09/02/kernel-hack-drill-and-CVE-2024-50264.html)
- [ARMO: Linux 6.17 security](https://www.armosec.io/blog/linux-6-17-security-features/)
- [kernelnewbies: Linux 6.13](https://kernelnewbies.org/Linux_6.13)
- [USENIX login: Kernel Isolation (KPTI)](https://www.usenix.org/system/files/login/articles/login_winter18_03_gruss.pdf)
- [sam4k: Random kmalloc caches](https://sam4k.com/exploring-linux-random-kmalloc-caches/)
- [Samsung KSPP study: heap overflows](https://samsung.github.io/kspp-study/heap-ovfl.html)
