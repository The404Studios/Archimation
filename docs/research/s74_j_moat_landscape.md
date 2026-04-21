# S74-J — Moat Analysis + Competitive Landscape

**Agent:** Research Agent J (S74 10-agent push)
**Date:** 2026-04-20
**Scope:** Is the S73 claim — *"the only Linux distro targeting all three Windows runtime tiers with a coherent authority model"* — actually defensible? Survey 14 comparator systems, identify the moat, propose 3-5 concrete widening moves.
**Mode:** Research only, no source edits.

---

## 0. TL;DR — The honest one-paragraph synthesis

ARCHIMATION occupies a genuinely unoccupied quadrant in the 2026 secure-OS
landscape: **Linux-native (not NT like ReactOS) + runs Windows binaries
user-mode AND attempts kernel-mode (not VM-isolated like Qubes, not
user-only like Wine/Proton/SteamOS) + kernel-rooted authority model (not
LSM-policy-only like SELinux/AppArmor/Landlock, not hypervisor-rooted like
Windows VBS/HVCI, not hardware-rooted-in-Microsoft-silicon like Pluton)**.
Within that quadrant, the only genuinely-novel primitives are the
**self-consuming Authority-Proof-Engine chain**, the **23-pair chromosomal
authority struct with XY-class inheritance bounds**, and the **6-family /
GPU-dispatchable trust ISA**. Everything else in the stack has superior
upstream-maintained equivalents we should either cooperate with
(Landlock, BPF-LSM, TPM2-PCR11, UKI, fs-verity) or stop claiming as moat
(more polish, more apps, biology vocabulary without an adversarial test
harness). Tier-3 (kernel-mode drivers) is the weakest part of the story
(30-40%) and is where no other Linux competitor tries because the 25-year
ReactOS lesson says it's the graveyard. Our competitive path forward is
to *lean harder into the one moat nobody else has* (APE + chromosome +
ISA) and explicitly stand on giants for everything else.

---

## 1. The 14 comparators — technical table

One row per system; six columns per the prompt. Ordering by increasing
architectural distance from ARCHIMATION.

| # | System                                         | Year / latest         | Problem solved                                            | Threat model                                                              | Authority model lives in                                           | Relation to ARCHIMATION                            |
|---|------------------------------------------------|-----------------------|-----------------------------------------------------------|---------------------------------------------------------------------------|--------------------------------------------------------------------|----------------------------------------------------|
| 1 | **Wine + Proton + DXVK + VKD3D**               | Wine 11.0 (Jan 2026); Proton 11 (Apr 2026); DXVK 2.78; VKD3D-Proton fork  | Run Windows user-mode apps/games on Linux without VM                      | Buggy-binary accidental misuse (NOT malicious code; Wine explicitly **does not sandbox**)  | **None.** Wine is a compat layer; trust lives in the host Linux kernel (DAC/LSM/namespace). | **Overlaps** tier 1. **Complement** — we can (and should, per S74 Agent 1) hand PE32 binaries to a Wine shim instead of reimplementing. |
| 2 | **SteamOS 3 (Valve, Arch-based)**              | 3.7 series (2026; kernel 6.14+)   | Gaming console UX on read-only Arch; Proton preloaded     | Accidental filesystem corruption, rollback of bad updates; NOT adversarial local code | **None beyond UEFI SB + btrfs A/B overlay + cgroups**. Proton runs as unprivileged user process. | **Overlaps** tier 1 delivery (ISO + ready-to-game). **Does not compete** on tier 2 (services) or tier 3 (drivers) or authority model. |
| 3 | **ReactOS 0.4.15**                             | 2025-03 (first release in 3.5 yrs) | Open-source NT kernel + userland reimplementation         | Legacy-hardware compatibility + FOSS Windows alternative; NOT a security product | The re-implemented NT object manager (SeAssignPrimaryToken etc.); same broken authority model as XP/2003  | **Direct conceptual competitor** on tiers 1-3. **Architecturally opposite**: they rewrite NT; we keep Linux. 30 years of effort, still alpha for kernel drivers because re-implementing NTOSKRNL correctly is an asymptote. |
| 4 | **Qubes OS 4.2**                               | 2024-06; still on Xen 4.17  | Compartmentalization by VM isolation                      | Sophisticated malware inside ONE qube must not escape                    | The **Xen hypervisor** + dom0 Qubes-GUI/policy daemons; Xen Security Modules (XSM-FLASK). | **Non-overlapping.** Qubes ships Windows via full HVM (QSB-091 currently blocks QWT install in 4.2). We run Windows processes natively in Linux. Different product, different buyer. |
| 5 | **Whonix / Tails / Heads**                     | Tails 6.x (2025); Whonix 17 | Network-level privacy; amnesia after reboot                | Traffic correlation, persistent malware, forensic recovery               | Tails: amnesic tmpfs. Whonix: Workstation VM cannot see network; Gateway VM forces Tor. | **Orthogonal.** Privacy posture; not a Windows-compat product. Useful as inspiration for disposable trust subjects. |
| 6 | **Secure Boot + TPM2 + measured boot (UEFI Forum / TCG)**        | UEFI 2.10 (2024); TCG PCCP 1.06; systemd-measure in sd 254+ | Boot-chain integrity; PCR attestation; **static** boot-time guarantee | Evil-maid, rootkits in pre-boot, ROM tampering (limited)                 | Platform firmware + shim + SBAT + dm-verity + UKI signed artifact measured into PCR 11 | **Prerequisite.** S72 Agent γ's trust_attest.c **already reads** PCR 11 and refuses init on mismatch. This is upstream-standard and we ride on top. |
| 7 | **systemd-integrity / dm-verity / fs-verity**  | fs-verity merged 5.4; dm-verity since 3.4; systemd-repart integrity since sd 253 | Block/file-level read-time integrity                       | Offline tampering of installed binaries and config                       | Filesystem-layer Merkle-tree root hash, signed by MOK/PK             | **Complement.** A composefs+fs-verity rootfs + our trust.ko gate = each binary is content-addressed (fs-verity) AND its execution is rate-metered (TRC) AND its authority is self-consuming (APE). No contradiction. S72 Containerfile already plans composefs. |
| 8 | **Linux LSMs: SELinux / AppArmor / Landlock / TOMOYO / Smack / Yama / IPE / LoadPin / SafeSetID / BPF-LSM** | Kernel 6.15+ stack; IPE merged 6.12 (Dec 2024); Landlock ABI 7 (6.15, audit) | Mandatory access control via policy at 158 kernel hooks   | Confused-deputy, policy-enforceable deny lists, unprivileged sandboxing  | A `struct security_hook_list` registered via `security_add_hooks()` at module init; policy in separate language (TE, AppArmor profile, BPF prog) | **Ground-truth check:** `grep -r 'register_security\|security_hook\|DEFINE_LSM' trust/kernel/` returns **zero**. trust.ko is **not an LSM**. It uses kprobes + /dev/trust ioctl RPC. This is a **refactor opportunity** (S71 Agent B found it first; still open as of S74). Landlock + BPF-LSM do what our `TRUST_ACTION_FILE_*` / `NET_*` denials do, better and cheaper. |
| 9 | **Microsoft Pluton**                           | 2022 launch; 2024+ AMD Ryzen Pro 6000+, Intel Core Ultra, Copilot+ PCs mandatory | Hardware root of trust inside CPU SoC die; TPM 2.0 compliant; firmware updated via Windows Update | Hardware attacker with bus access; firmware rollback; unofficial OS replacement (in some configs) | Microsoft-signed firmware inside Pluton core; the CPU vendor controls the silicon substrate. Some AMD Ryzen Pro skus refuse non-Microsoft bootloaders in certain firmware configs. | **Threat + opportunity.** Threat: Pluton-mandatory-locked SKUs refuse our shim/MOK chain → ARCHIMATION can't boot. Opportunity: where Pluton exposes TPM2 API, our trust_attest.c reads PCR 11 through it the same as discrete TPM. Mitigation path: AMD Ryzen non-Pro / Intel non-Core-Ultra / arm64 / RISC-V FPGA. |
| 10 | **Intel TDX / AMD SEV-SNP** (confidential computing)     | TDX production GA 2024; SEV-SNP since Milan 2021; 2025 ACM SIGMETRICS empirical study published | Protect VM from the hypervisor, host OS, other tenants, and physical memory attack  | Malicious cloud operator; compromised hypervisor; cold-boot on DIMMs   | CPU-enforced memory encryption (AES-XTS multi-key) + reverse map table (SNP) / TDX-module; attestation via SGX/TDX quotes  | **Compose, don't compete.** Running ARCHIMATION **inside** a TDX or SNP guest is coherent — their attestation proves the kernel memory is confidential; our APE proves in-guest actions are authoritatively ordered. Our S72 trust_attest.c reading PCR 11 is one layer; TDX quote would be an additional layer below. |
| 11 | **CHERI / Arm Morello**                        | Morello boards shipped 2022; CHERI-in-CHERI-Morello-Cerise proof-of-encapsulation accepted POPL 2025 (DOI 10.1145/3729329); VeriCHERI RTL proof ICCAD '24; ASPLOS 2024 formalisation of CHERI-C | Pointer-provenance + fine-grained memory capabilities at the hardware level  | Use-after-free, bounds violation, confused-deputy at the C-language level | CPU-enforced capabilities encoded as fat pointers; no software policy language at all | **Potentially our target substrate.** Our trust ISA's capability_mask is a software emulation of what CHERI does in hardware. If Morello consumer boards ship, a CHERI backend for trust_risc.c would make T4 (bounded inheritance) hardware-enforced for free. Parallel to the RISC-V FPGA plan. |
| 12 | **Android Verified Boot 2.0 + Titan M2**       | AVB 2.0 baseline since Android 8; Titan M2 in Pixel 6+ (2021), Pixel 10 (2025) | Chain-of-trust from ROM to system + vendor + /data integrity; rollback protection; StrongBox KM   | Persistent malware surviving factory-reset; bootloader tampering; attacker with physical access | ROM-fused keys in Titan M2 → bootloader → vbmeta → Merkle tree per partition via dm-verity | **Different device class**, same conceptual stack. Useful as *design precedent*: rollback-index + VBMeta is what our S72 bootc+TPM-PCR11 signed UKI is becoming. "Titan M2 for PC" is basically what Pluton is trying to be. |
| 13 | **Windows 11 VBS / HVCI / Credential Guard / Device Guard / HyperGuard** | Default-on since Win11 22H2 and Windows Server 2025  | Move kernel-mode-code-integrity enforcement **out of** the NT kernel **into** the Hyper-V root  | NT kernel is assumed compromised; isolate secrets (LSASS NTLM/Kerberos) + CI in VTL1 | The Hyper-V hypervisor (VTL0 = NT kernel, VTL1 = "SecureKernel"); credentials in isolated VSM memory encrypted by hypervisor; 5-15% perf tax | **Architectural mirror.** Microsoft's answer to "can we trust the kernel?" is "no, move root of trust up one level into the hypervisor." Our answer is "yes, if we build a kernel module whose state is self-consuming and whose every action is proof-entangled." These are **philosophically opposite** approaches to the same gap. VBS+HVCI is more deployed; trust.ko is more novel. |
| 14 | **Genode + seL4 (formally-verified microkernel)** | seL4 12.x (2024); Atoll hypervisor + Pancake driver verification 2024-2025 summit; Genode 25.x | Formal proof of OS-kernel functional correctness + information-flow noninterference; capability-based IPC  | Bug in any user process, driver, or application; NOT vendor-backdoor | seL4 CSpace (capability address space per thread), verified against abstract spec in Isabelle/HOL | **Gold-standard substitute.** The only OS kernel that can claim more rigorous authority guarantees than trust.ko is seL4 (because seL4's guarantees are machine-checked proofs, ours are 7 theorems with sysfs violation counters that have never been adversarially exercised). Porting our APE + chromosome + ISA into a Genode component on seL4 is the sober long-game (5-10 years). |

---

## 2. The unoccupied quadrant — is it actually unoccupied?

Claim to defend: *"ARCHIMATION is genuinely positioned to be the only Linux
distro targeting all three Windows runtime tiers with a coherent authority
model."*

Let's check that sentence piece by piece.

### 2.1  "Only Linux distro"
- ReactOS is NOT Linux (its own NT re-implementation). ✓ differentiated.
- SteamOS 3 IS Linux (Arch-based) but abandons tier 2+3. ✓ differentiated.
- Qubes IS Linux (dom0 Fedora) but runs Windows as VM. ✓ differentiated.
- Fedora Silverblue/Kinoite, Nix, Endless, openSUSE MicroOS etc. ship
  Linux immutably but have no Windows-runtime story. ✓ differentiated.
- The CrossOver/CodeWeavers stack runs on Linux but is ship-on-top, not
  a distro. ✓ differentiated.

**Verdict**: "Only Linux distro" holds if we also say "targeting all three
tiers". Purely tier-1-focused gaming distros (Bazzite, CachyOS, ChimeraOS)
exist and do it very well; they explicitly do not try tiers 2 or 3.

### 2.2  "All three Windows runtime tiers"
- Tier 1 (apps): pe-loader loader + 37 DLL stubs + DXVK/VKD3D. Our paper
  validation memo says 80%. PE corpus on pkg-23 is 16/18. Wine/Proton is
  ~95%+ on the same measure but via 25 years of CompatBin matrix. **Wine
  is ahead on tier 1.**
- Tier 2 (services): SCM with topo sort, restart policy, svchost SHARE_PROCESS
  grouping. **No FOSS equivalent ships tier 2 at all.** Wine has a
  wineserver for IPC but not Windows-service-lifecycle semantics.
  CrossOver doesn't try. ReactOS does but their SCM is alpha.
  **We're alone here.**
- Tier 3 (drivers): wdm_host.ko skeleton + 27-fn ntoskrnl symbol + Authenticode
  shape check + TRUST_ACTION_LOAD_KERNEL_BINARY gate. Paper-validation
  memo says 30-40%. **ReactOS has been grinding on tier 3 for 25 years and
  is still in 0.4.15 with partial PnP.** Wine explicitly does not attempt
  tier 3. If we ship a single first-party WDM driver under hardware trust
  gating, **we're the only open-source Linux project that has shipped one
  at all**. That's also where the credibility risk is largest because
  "works" for tier 3 is not "hello world loads" — it's "runs a real-world
  driver under real workload without oops".

**Verdict**: "All three tiers" is defensible IF we're explicit that
"targeting" ≠ "achieving." Tier 1 is ~equal to Wine; tier 2 we own
outright but the market doesn't yet know they need it; tier 3 is the
long road and the claim there is aspirational.

### 2.3  "Coherent authority model"
- Qubes has an authority model: it lives in the hypervisor. Coherent but
  *different* — it's about VM isolation, not process-internal trust scoring.
- Windows 11 VBS/HVCI has an authority model: it also lives in the
  hypervisor (Hyper-V VTL1). Coherent. Well-deployed. But not open and
  not applicable to Linux userspace.
- SELinux + Landlock + BPF-LSM is coherent but it's a *policy* model —
  "thing X is allowed to do Y" — not an *authority* model where Y costs
  tokens, proofs self-consume, and chromosomal inheritance bounds apply.
- seL4 is the only FOSS kernel with a coherent, formally-verified authority
  model (capabilities). Their capabilities are static; ours are dynamic
  with hysteresis decay + proof chains.

**Verdict**: "Coherent authority model" is correct if you mean *dynamic*
authority. The three capabilities that are genuinely not reproducible in
upstream Linux (per S71 Agent B's analysis, confirmed by S74-J grep):

1. **APE self-consuming proofs** — no LSM, no TPM, no capability system
   has destroy-on-read authorization tokens with reconfigurable-hash
   chaining.
2. **Dynamic trust score with continuous decay** — LSMs are binary
   allow/deny; TPM2 quotes are point-in-time; capabilities are static.
3. **Token-economy metabolic fairness (Theorem 6)** — cgroups rate-limit
   CPU/IO, not action-class.

---

## 3. The moat, honestly enumerated

The S73 convergence work gives us 12 bio/math frameworks. The tier audit
gives us 6 product axes. The landscape gives us 14 comparators. Boiling
all three down to "what can nobody else reproduce":

### 3.1  Genuinely novel (would survive peer review)

| Primitive                                                 | Why nobody else has it                                                                     | Evidence of novelty                                              | Peer-review risk level      |
|-----------------------------------------------------------|--------------------------------------------------------------------------------------------|------------------------------------------------------------------|-----------------------------|
| Authority Proof Engine (APE) with self-consuming proofs   | Reconfigurable-hash chain with destroy-on-read; 94,371,840 distinct hash configs per step. No LSM, no TPM command, no capability system has this shape. Closest analog is **one-shot quantum signatures** (BTQ 2024, eprint 2025/486) which require quantum hardware — ours is classical. | `trust_ape.c` 655 LOC; paper §APE; `trust_ape.h` Theorem 3 (cfg reconfiguration). Literature search: 0 matches for "self-consuming proof" in OS-security context. | **LOW.** The primitive is well-defined and mechanically inspectable. Adversarial harness needed for T2/T3 claims. |
| 23-pair chromosomal authority struct with XY sex determination  | Nobody models subjects as a (runtime, construction) chromosome pair with meiotic divergence detection. SELinux has "domains" but they're flat labels; seL4 has CSpaces but they're flat capabilities. | `trust/include/trust_chromosome.h:#define TRUST_CHR_A_COUNT 23`; `trust_chromosome.c:149-153` the four sex classes (XX/XY/YX/YY). | **MEDIUM.** Vocabulary is gorgeous and unique; reviewers may ask "what does 23 buy you vs 16 vs 32?" and the answer is non-obvious. Biology analogy may earn skepticism not points. |
| 6-family × 32-bit RISC ISA for trust operations, GPU-dispatchable | No other authority kernel is a stored-program interpreter with fused ops and a GPU command-buffer model. | `trust/include/trust_isa.h`; `trust_risc.c` 498 LOC. 6 families (AUTH/TRUST/GATE/RES/LIFE/META). | **LOW** if we can show the ISA actually gets used (is every path through the kernel a sequence of ISA ops?). **HIGH** if the claim is architectural but most code paths bypass the ISA. **Need to audit.** |
| Theorem 6 metabolic fairness (bounded action-class throughput) | cgroups limit CPU/memory; no Linux system limits action **classes** (opens, signals, connects) in a unified token ledger with per-action TRC cost multiplier. | `trust_authz.c:61` (`trust_token_burn_with_trc`); TRC fixed-point 8.8 cost_multiplier. | **LOW-MEDIUM.** Concept is clean; implementation coverage needs demonstration. |
| Theorem 4 bounded authority inheritance (chromosomal) | Static LSM contexts can transition, but no system bounds inheritance via chromosomal merge (A⊕B / A∩B) at fork. | `trust_meiosis.c` + `trust_chromosome.c` sex class → parent allele selection. | **MEDIUM-LOW.** Need adversarial harness: deliberately fork with mismatched chromosomes and assert bound holds. |

**Total novel LOC**: APE (655) + chromosome (255) + ISA (498) + lifecycle
(1004) + attest (439) + authz (735) + core (1019) + ape_markov (221)
= ~5000 LOC of genuinely-unique kernel C. Plus the paper itself.

### 3.2  Strong-but-not-unique (still valuable moat)

| Primitive | Prior art exists |
|---|---|
| AI cortex ↔ kernel with algedonic bypass | Beer VSM 1972, Friston active inference 2006+; prior art is textbook. **Novelty is the combination with authority kernel**, not the concepts. |
| Biological vocabulary (chromosome/meiosis/tissue/morphogen) | Artificial Immune Systems literature 2003+; IoT-AIS papers 2020-2024. **Our contribution is specifically mapping these to kernel authority**, not inventing the bio-metaphor. |
| Windows-compat on Linux with kernel gate | SteamOS + Proton + BPF-LSM + systemd cgroup could be composed to do this. Nobody has. |
| Composefs + fs-verity + dm-verity + bootc image | All upstream. Our work in S72 is plumbing them into a coherent image build, not inventing any of them. |
| 45K NL phrase dictionary for /cortex routing | Unique to us but accidentally-moated; commodity tech would beat it eventually. |

### 3.3  Claimed-moat that wouldn't survive scrutiny

**These are marketing claims, not defensible claims. Call them out here so
we stop leaning on them.**

- **"Runs Windows drivers."** We're 30-40% there per the tier-audit memo;
  wdm_host.ko has IAT walker + 27 ntoskrnl fns + Authenticode shape check,
  but hundreds of WDM/WDF entry points are missing, no IRP_MJ dispatch
  table, no PnP arbitration. A real-world .sys driver would oops. The
  HONEST claim is "we have a skeleton for gated driver loading that
  refuses everything by default, which is safer than Wine which refuses
  drivers categorically."
- **"Biologically-inspired."** This is a teachability aid. It is **not**
  a technical property. Peer reviewers at USENIX Security / CCS / IEEE S&P
  will ask "which property is emergent from biology and which would hold
  without the metaphor?" Answer for most: would hold. So we should
  lead with the mathematical properties (theorems + ISA + APE algebra)
  and use biology as pedagogy, not argument.
- **"Adversarially validated."** Trust.ko has never been run against a
  red-team. Its seven sysfs violation counters have sat at 0 under clean
  load. S73-F's self-attestation idea is the only thing that would force
  a live violation; it's still aspirational. **This is the biggest gap
  between our self-perception and our defensible claim.**
- **"FPGA-validated hardware substrate."** The paper's RISC-V FPGA POC
  was not publicly reproduced. We're x86_64 Linux kernel module. The
  S74 Agent 4 RISC-V QEMU Phase 1 is the cheapest honest step toward
  that claim.
- **"AI cortex cannot originate, only veto."** Safety claim that's not
  currently mechanically enforced. There's no type-level or kernel-level
  guard that the cortex handler API is veto-only. A malicious cortex
  could call `trust_action` as easily as `trust_veto`. Needs a typestate
  audit before we can defend the sentence.

### 3.4  What's left after the honest cut

The **defensible moat** is:
1. APE + chromosome + ISA as mathematical objects (5000 LOC, paper-cited).
2. Ground trust in the Linux kernel instead of a hypervisor — a design
   **choice** with real trade-offs vs. VBS/HVCI/Qubes, defensible IF
   we can articulate when to pick ours (low overhead, single-tenant dev
   box) vs. theirs (multi-tenant cloud, Windows-first shops).
3. The combination: Windows-binary-execution + Linux-kernel-trust-root in
   one product. Nobody else delivers this combination (Wine/Proton does
   the execution without trust root; Qubes does trust without native
   execution).
4. The 7-theorem paper authored by the same person who wrote the code.
   This is *authorial coherence* — there's no translation gap between
   spec and implementation. Few systems have this; it's a real moat for
   trust/audit reasons.

---

## 4. Deep dives on the six highest-signal comparators

### 4.1  Wine/Proton/DXVK — the quiet giant

- **Wine 11** (January 2026) ships with NTSYNC in the mainline kernel
  (6.14+). Games using direct syscalls (Detroit: Become Human, RDR2) now
  work in mainline Wine 11.5 (March 2026), not just Proton.
- **Proton 11** (April 2026) rebases on Wine 11, ships DXVK 2.78,
  and adds FSR4 support. Valve has added NTSYNC kernel driver to
  SteamOS 3.7.20 beta, loading by default.
- **Anti-cheat**: EAC and BattlEye now support Proton when developer
  enables it, but runs at **user level not kernel level**. Are-We-Anti-Cheat-Yet
  tracks per-game status.
- **Trust story**: None. Wine does not sandbox; documentation explicitly
  says don't run unsigned Windows binaries you wouldn't run on Windows.

**Implications for ARCHIMATION:**
- Reimplementing user-mode Win32 is tilting at a 9M-LOC windmill with
  25 years of developer-years behind it. **S74 Agent 1 (Wine PE32 shim)
  is the correct call.** We should pass through PE32+ compatibility to
  Wine for everything except the cases where our trust gate *has* to see
  the syscall. Those cases = kernel-mode things (i.e. NT-driver loads,
  `NtLoadDriver`) and specific authority-sensitive actions.
- **Differentiation**: trust-gating the Wine process itself. A
  `libtrust_wine_shim.so` via `LD_PRELOAD` can intercept Wine's syscall
  layer and apply our APE + TRC + chromosome semantics. We get Wine's
  compat *and* our moat. This is defensible and doesn't exist.

### 4.2  ReactOS — the 30-year cautionary tale

- 0.4.15 released March 2025, **first release in 3.5 years**.
- Headline: PnP Manager rewrites (by Victor Perevertkin) finally let it
  boot from USB and use MS FAT driver from WDK. Still alpha.
- Under development: UEFI, SMP, new graphical installer, new NTFS driver,
  power management. **Note what's NOT finished in 30 years: any of those
  things.**
- Kernel API coverage is the bottleneck. NTOSKRNL is documented but
  semantic-edge-case-heavy; re-implementing it correctly takes forever.

**Implications:**
- **This is why the Linux-native kernel decision is load-bearing.** We get
  Linux's PnP, NTFS-3g, power management, SMP for free. trust.ko adds
  authority gating on top; wdm_host.ko adds Windows-driver-hosting on
  top. If we were trying to reimplement NTOSKRNL we would be where
  ReactOS is.
- **Tier 3 is their whole project**, and they're not done. Our claim
  "30-40% of tier 3" is believable *only because* we delegate most of
  the kernel to Linux and only re-implement the Windows-driver ABI bridge.
  Keep that honest framing.

### 4.3  Qubes OS — the principled-isolation competitor

- 4.2 released 2024-06; Qubes Windows Tools (QWT) installation is
  **currently blocked** due to QSB-091 (compromised Xen driver sources).
- Xen HVM has QEMU in a stubdomain + seccomp sandbox but stubdomain is
  significant hypercall attack surface.
- Threat model: sophisticated malware inside one qube must not escape to
  another qube or dom0. This is about **preventing lateral movement
  after a compromise** — very different from our threat model which is
  **preventing unauthorized action at the point of attempt**.

**Implications:**
- **Non-overlapping product.** A CISO choosing between Qubes and
  ARCHIMATION is evaluating "how do I contain a breach" (Qubes) vs "how
  do I prevent the action" (us). Both are valid; both are defensible.
- Qubes runs Windows only as HVM (slow, disposable, currently security-broken).
  We run Windows as native Linux process under kernel gate (fast, on the
  host). **Neither is better; they're answers to different questions.**

### 4.4  Microsoft Pluton — the silicon-level threat

- Integrated in CPU SoC die since 2022; mandatory in Copilot+ PCs (2024+).
- Dedicated updatable firmware, Rust-based per 2024 roadmap.
- **Real adoption concern for us**: AMD Ryzen Pro 6000+ with Pluton in
  some configurations refuse non-Microsoft bootloaders. KitGuru 2022
  documented this; OSnews/mjg59 countered that it's currently opt-in on
  most PCs. Lenovo ships Pluton opt-in (off by default).

**Implications:**
- **Where Pluton exposes TPM2 interface**, we cooperate. Our S72 Agent γ
  trust_attest.c reads PCR 11 via tpm2 sysfs regardless of whether
  backing is discrete TPM, fTPM, or Pluton.
- **Where Pluton locks bootloader**, we don't run. The mitigation is:
  document supported hardware list; offer arm64 path; FPGA RISC-V path
  for fully open substrate.
- **Philosophically**: Pluton is Microsoft's answer to "can you trust the
  root?" → "only if we made the root." ARCHIMATION's answer: "yes, if the
  root is an open-source self-consuming proof chain whose .text is
  hashed into every proof (S73-F). No vendor secret required."

### 4.5  Windows 11 VBS / HVCI — the architectural mirror

- Default-on in Windows 11 22H2+ and Windows Server 2025.
- Hyper-V hypervisor runs VTL1 "SecureKernel" holding LSASS secrets;
  VTL0 runs regular NT kernel.
- HVCI (aka Memory Integrity) enforces KMCI in VTL1 so VTL0 NT kernel
  cannot load unsigned/unauthorized driver code.
- **5-15% perf penalty** per Tom's Hardware 2024. Hardware req: Intel
  Kaby-Lake+ MBEC or AMD Zen 2+ guest-mode execute trap.

**Implications:**
- This is Microsoft's architectural choice to solve "the NT kernel is
  too big to trust." Our choice: "we can build a small Linux kernel
  module whose state is self-consuming and externally verifiable via
  PCR 11, so we don't need a hypervisor." Both are valid positions; they
  disagree about how much to trust the kernel.
- **If someone ships Linux-on-KVM with trust.ko running as a VM in a
  guarded VTL1-analog**, that would be the strongest possible architecture
  (our novel trust primitives + Microsoft's battle-tested isolation).
  We're not proposing this, but it's the path to "best of both worlds".

### 4.6  seL4 — the gold standard for authority proof

- Only general-purpose OS kernel with a machine-checked proof of
  functional correctness (original POS'09 paper; kept current for 15+ years).
- 2024-2025 Atoll hypervisor-on-seL4 + formally-verified Ethernet driver
  via Pancake / Viper framework.
- Capability-based: every thread has a CSpace of capabilities; no
  ambient authority.

**Implications:**
- This is the **credibility benchmark we will be compared against** at
  security conferences. They have proofs; we have theorem claims with
  sysfs counters that have never been adversarially exercised.
- **Long-game path**: Port APE + chromosome + ISA into a Genode component
  running on seL4. 5-10 year horizon. Gives us formal backing for the
  pieces of the authority model that matter.
- **Short-game**: Adopt a rigorous adversarial test harness so the
  theorem counters actually move under attack. This is the single
  highest-signal thing we can do before a conference submission.

---

## 5. Five concrete moat-widening proposals

Ranked by marginal-moat-value / session-cost. Each aligned with our
unique substrate (not the upstream we should be cooperating with).

### Proposal A: Adversarial Theorem Harness (T1–T7) — HIGH VALUE, 1-2 SESSIONS

**What:** A new test suite `tests/adversarial/theorem_violation_suite.py`
that deliberately attempts to violate each of T1-T7 and asserts that:
(a) the relevant sysfs `/sys/kernel/trust_invariants/theoremN_violations`
counter increments, (b) the kernel refuses the action, (c) no privilege
escape occurs. Eight test classes:

- T1 Non-Static Secrets: attempt to snapshot APE state twice, compare,
  assert every byte different.
- T2 Non-Replayability: replay a recorded proof; assert refused.
- T3 Forward Secrecy: capture state, derive prior state, measure entropy.
- T4 Bounded Inheritance: fork with mismatched chromosome; assert
  `trust_chromosome_bound_inheritance()` enforces merge rule.
- T5 Guaranteed Revocation O(1): revoke subject, measure latency p99.
- T6 Metabolic Fairness: hot-loop action burner; assert TRC starves it.
- T7 Statistical Anomaly: feed uniform random syscall distribution,
  assert chi-square violation counter increments.

**LOC estimate**: ~800 Python + ~50 C helpers.
**Why it widens the moat**: Takes the paper's claims from "asserted" to
"demonstrated." Makes every future peer-review conversation start with
"here are the attempted violations and here's the counter behavior"
instead of "trust us, it holds."
**Why nobody else is doing it**: Because nobody else has this specific
theorem set. seL4 has proofs, not harnesses; LSMs have policy, not
theorems.

### Proposal B: libtrust_wine_shim — Wine Under the Trust Gate — HIGH VALUE, 2-3 SESSIONS

**What:** `LD_PRELOAD`'d shared object intercepting Wine's NT syscall
entry points (`ntdll!NtXxx` lookups in wineserver IPC), applying APE
consumption + TRC cost multiplier + chromosome-typed subject creation
per Wine process.

**Architecture:**
```
WINE process
   └─ .exe is not our problem
   └─ ntdll.dll.so (Wine's)
        └─ NtCreateFile, NtOpenFile, NtDeviceIoControlFile, NtLoadDriver
              └─ LD_PRELOAD libtrust_wine_shim.so intercepts
                   └─ /dev/trust TRUST_ACTION_FILE_OPEN / ACTION_NET_CONNECT
                        └─ APE consume + TRC burn + chromosome subject
```

**LOC estimate**: ~1200 C (shim) + ~200 unit-test in a Wine prefix.
**Why it widens the moat**: Turns Wine's coverage (our weakest tier 1
delivery mechanism) into OUR competitive advantage. For the first time:
"run any Windows app via Wine, and every NT syscall is authority-gated
by trust.ko." Nobody else offers this combination.
**Why nobody else is doing it**: Wine community explicitly does not
sandbox; LSM community doesn't know Wine exists; trust.ko doesn't exist
elsewhere. Unique intersection.

### Proposal C: Self-Attestation Quine — S73-F, Lifted — HIGH VALUE, 1 SESSION

**What:** S73 Agent F proposed `trust_ape_verify_self()` — fold
SHA-256(trust.ko's own `.text`) into every APE proof. A modified live
module disagrees with itself → every proof breaks.

**Implementation**: Build-time SHA-256 of `trust.ko` `.text` segment into
a `.build_hash` section; runtime `kallsyms_lookup_name("_stext")` +
`sha256_init`/`update` over the .text extent; XOR into APE config. Any
kernel-level code patching immediately breaks the proof chain.

**LOC estimate**: ~250 C in trust_ape.c + trust_core.c.
**Why it widens the moat**: Addresses the single biggest credibility gap
(§3.3: "adversarially validated"). Gives us a live-reflexivity property
that Windows HVCI doesn't have (HVCI checks at load; ours checks at
every action). Pairs naturally with Proposal A's harness.
**Why nobody else is doing it**: Because most LSMs are policy-only and
don't have a proof chain to fold self-hash into.

### Proposal D: Trust ISA ↔ CHERI Backend (Optional Substrate) — LOW-MED VALUE, 3-4 SESSIONS

**What:** Scaffold a CHERI backend for `trust_risc.c` that emits capability
instructions on Morello instead of x86_64 trust-ISA ops. T4 (bounded
inheritance) becomes hardware-enforced via capability bounds; no software
check needed.

**LOC estimate**: ~600 C + CHERI-ABI glue, assuming Morello board in hand.
**Why it widens the moat**: Turns a software theorem claim into a
hardware-enforced property. Validates the ISA design against a
real capability substrate — not just our x86_64 software emulation.
Parallel to the RISC-V FPGA plan; CHERI has the bigger payoff because
bounded-inheritance is an existing Morello primitive.
**Why nobody else is doing it**: CHERI papers focus on pointer provenance
for memory safety; nobody has proposed capabilities as the substrate for
a dynamic authority-score system. Novel research contribution, not just
engineering.
**Session cost**: Real; depends on Morello access. Parallel to Agent 4's
RISC-V Phase 1. **Flag as S75+ — not S74.**

### Proposal E: Catalysis + Assembly + Entropy Ratchet (S73 Cluster 3) — MEDIUM VALUE, ALREADY IN S74

**What:** S74 Agent 7 is scheduled to ship `entropy_observer.py` +
`assembly_index.py`. The widening move: make these gates *ratcheting*,
not just measuring. Once a subject drops below an entropy floor, it
cannot climb back without an explicit elevate action (audited, TRC-costed).

**LOC estimate**: Already in S74 Agent 7 (~440 LOC). The "ratchet" add-on
is ~80 LOC.
**Why it widens the moat**: Polymorphic malware / UPX-packed binaries /
ML-generated code are currently getting past behavioral baselines
across the industry. Assembly-index-gating at the APE level is genuinely
novel. Combined with catalysis CI (Agent 9), we have a triad nobody
else has: byte-entropy + code-assembly + call-graph-catalysis gates.
**Why nobody else is doing it**: These are three different
literatures (Shannon/Bennett + Cronin-Walker + Kauffman) that nobody has
fused into an OS-authority gate.

---

## 6. Three widening proposals NOT to pursue

Useful to name rejects so we don't drift.

### Reject: "More Windows-app compat"
Fastest way to burn credibility. Wine has 25 yrs, Proton has 7 yrs of
game-matrix data, we have pkg-23. Competing on total app coverage is a
losing play. **Delegate to Wine shim (Proposal B).**

### Reject: "Full formal verification of trust.ko"
5-10 year effort, requires Isabelle/HOL expertise (ours is seL4-level
theorem proving = 20 person-years). Instead: adversarial harness
(Proposal A) + self-attestation (Proposal C) get 80% of the peer-review
credibility at 5% of the cost.

### Reject: "Own hypervisor / own microkernel"
The "ARCHIMATION-on-seL4" long game is valuable as a 5-10 year R&D
path, but building our own hypervisor (a la VBS) or microkernel (a la
seL4/Genode) in-session-scale is not reasonable. We'd reinvent 15 years
of upstream at quarter-quality. Instead: **cooperate with TDX/SNP guests
and (optionally) port to Genode-on-seL4 over multi-year horizon.**

---

## 7. Peer-review simulation: "what if we submitted to USENIX Security tomorrow"

I imagine a hostile-but-fair senior PC member. Their predicted comments:

### Probable accept
- "Self-consuming proof chain with reconfigurable-hash step is a
  genuinely novel primitive. Formal algebra + adversarial harness
  (Proposal A) would be sufficient for a short paper."
- "The authority-kernel-gated Windows-binary combination is novel and
  the use of libtrust_wine_shim (Proposal B) makes a compelling
  end-to-end story."

### Probable major-revision
- "Theorem 6 metabolic fairness is a nice claim but never measured.
  Ship the adversarial T6 test and we'll reconsider."
- "What does the biology vocabulary BUY you? If every claim can be
  re-stated without 'chromosome' or 'meiosis', drop the vocabulary;
  if not, define which property is chromosome-dependent." (Answer:
  the XY sex classes encode the specific {A-parent, B-parent}
  divergence analysis that bounds inheritance at fork. Without
  chromosomes, it's an ad-hoc rule. We should lead with that.)
- "No independent substrate reproduction. The paper's FPGA claim is
  unverified." (Answer: S74 Agent 4 is the first step.)

### Probable reject
- "Tier 3 Windows driver claim is aspirational and the claim as stated
  is unfalsifiable." (Answer: we drop the Tier 3 claim from the paper
  entirely and move it to "future work" — ReactOS's 30-year history
  is the warning. Tier 3 stays in the product story, not the academic
  submission.)

### Probable ignore
- "The AI-cortex is not differentiated enough from existing
  decision-engine literature." (Answer: the paper need not make cortex
  claims to sell the trust claim. Decouple for the paper.)

**Submission strategy**: The minimum publishable unit is
**APE + chromosome + ISA + Theorem T4 T5 T6 harness + libtrust_wine_shim**.
Tier 3 drivers, AI cortex, biology vocabulary as pedagogy = move to
separate papers or product white-papers.

---

## 8. Competitive positioning summary (one-table)

| Dimension                | Us           | Wine/Proton | SteamOS 3    | ReactOS    | Qubes 4.2    | seL4/Genode  | Win11 VBS/HVCI |
|--------------------------|--------------|-------------|--------------|------------|--------------|--------------|----------------|
| Runs Windows apps        | ~80% (PE+Mono+CRT) | ~95% (mature)  | ~95% via Proton | alpha       | via HVM      | no (Linux in Genode) | native         |
| Runs Windows services    | YES (SCM)    | NO          | NO           | alpha      | NO           | NO           | native         |
| Runs Windows drivers     | skeleton     | NO          | NO           | alpha-PnP  | limited HVM  | NO           | via HVCI       |
| Linux-native             | YES          | YES         | YES          | NO         | YES (dom0)   | NO (µkernel) | NO             |
| Kernel-rooted trust      | YES trust.ko | no          | no           | no         | Xen (hyp-rooted) | µkernel caps | VTL1 (hyp-rooted) |
| Self-consuming proofs    | **YES APE**  | no          | no           | no         | no           | no           | no             |
| Dynamic trust score      | YES          | no          | no           | no         | no           | no (static caps) | no         |
| Chromosomal authority    | **YES**      | no          | no           | no         | no           | no           | no             |
| Trust RISC ISA (dispatchable) | **YES** | no          | no           | no         | no           | no           | no             |
| Formal verification      | 7 theorems, sysfs counters, no harness | no | no | no | partial (XSM-FLASK) | **YES machine-checked** | partial |
| Adversarial review       | none         | community 25yrs | battle-tested via Steam Deck | hobbyist | active maintainers | academic + Atoll prod | MSRC + MS-fleet |
| Hardware root            | PCR 11 attest | no         | SB-opt       | no         | XSM           | board-dep    | Pluton/TPM2     |
| Runs on old HW           | YES (old-hw mode) | YES     | YES (Deck)   | YES        | strict HCL   | dev-board    | TPM2 required   |

**The intersection where we're alone**: YES-YES-YES on rows 2, 3 (limited),
4, 5, 6, 7, 8, 9. No competitor populates all of those at once.

---

## 9. Summary — what the S73 claim actually is, cleaned up

The literal S73 statement is:

> "ARCHIMATION is genuinely positioned to be the only Linux distro
> targeting all three Windows runtime tiers with a coherent authority
> model."

Audited version:

> ARCHIMATION is the only Linux distro that *attempts* all three Windows
> runtime tiers (apps via PE loader + DLL stubs + Mono, services via SCM,
> drivers via wdm_host.ko skeleton) under a dynamic authority model whose
> novel primitives — Authority Proof Engine with self-consuming proofs,
> 23-pair chromosomal authority struct with XY-class inheritance bounds,
> and a 6-family dispatchable trust RISC ISA — are not reproduced in
> upstream Linux (SELinux/AppArmor/Landlock/BPF-LSM/TPM2), in Wine/Proton,
> in SteamOS, in Qubes, in ReactOS, or in seL4/Genode. The claim is
> defensible for tiers 1-2; aspirational for tier 3. The authority-model
> claim is defensible for the three named primitives; not yet for the
> adversarial-validation sense. Competitive path forward: ship the
> adversarial theorem harness (Proposal A), the libtrust_wine_shim
> (Proposal B), and the self-attestation quine (Proposal C) to close
> the gap between asserted and demonstrated. Stop leaning on
> biology-vocabulary and "runs Windows drivers" as moat; lead with the
> mathematics. Cooperate explicitly with TPM2/PCR11, composefs, fs-verity,
> Landlock, and BPF-LSM as prerequisites, not competitors.

That sentence is the honest thesis. It's narrower than the marketing
version and much more defensible.

---

## 10. Open questions surfaced by this audit

- **Is the trust ISA actually used?** Need an audit of which `/dev/trust`
  ioctl paths dispatch through `trust_risc.c` vs. bypass it. If the ISA
  is mostly decorative (most paths call C helpers directly), the novelty
  claim weakens. If it's load-bearing, the ISA + GPU-dispatch claim is
  strong. **Suggested S75 agent task.**
- **Typestate enforcement of AI-cortex-only-vetoes.** Is there a
  compile-time guarantee that cortex code cannot originate actions, or
  is it a handler-naming convention? Matters for the safety claim.
  **Grep for `trust_cortex_action` vs `trust_cortex_veto` — if both
  exist as syscalls, the claim is weakened.**
- **Does the 27-instruction ISA table match the paper exactly?** Paper
  claims 27; our audit memo said 14 explicit + tags + fused ≈ 30.
  Reconciliation needed.
- **Pluton-locked-SKU exclusion list**: curate a known-bad hardware
  list so users don't waste hours on AMD Ryzen Pro systems that refuse
  non-MSFT bootloaders. **Suggested documentation task.**
- **Threat-model document.** We don't have a published one. Every
  comparator in §1 has an explicit threat model; we imply one by the
  theorem names but never enumerate adversaries. **Suggested S75 agent
  task.**

---

## 11. Citations (56 sources, 2020-2026)

### Comparator systems
1. Wikipedia contributors. "Wine (software)." <https://en.wikipedia.org/wiki/Wine_(software)>
2. Wikipedia contributors. "Proton (software)." <https://en.wikipedia.org/wiki/Proton_(software)>
3. thegeek.games. "Proton: Valve Takes Another Huge Step Forward With Wine 11 Integration!" 2026-04-19. <https://thegeek.games/2026/04/19/proton-valve-takes-another-huge-step-forward-with-wine-11-integration/>
4. WCCFTech. "Valve Quietly Rebased Proton on Wine 11..." 2026. <https://wccftech.com/valve-quietly-rebased-proton-on-wine-11-and-linux-gaming-just-got-windows-level-frame-pacing/>
5. HansKristian-Work. "vkd3d-proton." <https://github.com/HansKristian-Work/vkd3d-proton>
6. XDA-Developers. "Wine 11 rewrites how Linux runs Windows games at the kernel level." 2026. <https://www.xda-developers.com/wine-11-rewrites-linux-runs-windows-games-speed-gains/>
7. Phoronix. "Wine 10.15 To Feature Initial Support For Using NTSYNC On Linux." <https://www.phoronix.com/news/Wine-10.15-With-NTSYNC>
8. Are-We-Anti-Cheat-Yet. <https://areweanticheatyet.com/>
9. Wikipedia. "SteamOS." <https://en.wikipedia.org/wiki/SteamOS>
10. 9to5Linux. "Valve Says SteamOS 3.0 Will Be Available for Everyone." <https://9to5linux.com/valve-says-steamos-3-0-will-be-available-for-everyone-to-download-and-install>
11. LWN. "Linux ecosystem contributions from SteamOS." <https://lwn.net/Articles/946188/>
12. ReactOS Project. "ReactOS 0.4.15 released." 2025-03. <https://reactos.org/project-news/reactos-0415-released/>
13. Phoronix. "ReactOS 0.4.15 Released..." 2025. <https://www.phoronix.com/news/ReactOS-0.4.15-Released>
14. The Register. "ReactOS emits release 0.4.15 – first since 2021." 2025. <https://www.theregister.com/2025/03/25/reactos_drops_release_0415/>
15. Neowin. "Open source Windows ReactOS gets shell, plug-n-play, file system, Registry upgrades, more." 2025.
16. Qubes OS. "Standalones and HVMs." <https://doc.qubes-os.org/en/latest/user/advanced-topics/standalones-and-hvms.html>
17. Qubes OS. "Qubes Windows Tools (QWT)." <https://doc.qubes-os.org/en/latest/user/templates/windows/qubes-windows-tools.html>
18. Qubes OS. "How to install Windows qubes in Qubes OS." <https://doc.qubes-os.org/en/latest/user/templates/windows/qubes-windows.html>
19. Qubes OS. "Frequently asked questions (FAQ)." <https://doc.qubes-os.org/en/latest/introduction/faq.html>
20. linuxmind.dev. "Complete OS Guide: Qubes OS How It Works, Orientation and Curiosities." 2025-09. <https://linuxmind.dev/2025/09/04/complete-os-guide-qubes-os-how-it-works-orientation-and-curiosities/>
21. StationX. "Whonix vs Tails (Differences You Must Know in 2026)." <https://www.stationx.net/whonix-vs-tails/>
22. StateOfSurveillance.org. "Privacy Live Distros: Tails, Whonix, and Amnesic Systems." <https://stateofsurveillance.org/guides/advanced/privacy-live-distros-comparison/>
23. dasroot.net. "Privacy-Focused Operating Systems: Qubes, Tails, Whonix." 2026-03. <https://dasroot.net/posts/2026/03/privacy-focused-operating-systems-qubes-tails-whonix/>
24. ArchWiki. "Trusted Platform Module." <https://wiki.archlinux.org/title/Trusted_Platform_Module>
25. ArchWiki. "Unified Extensible Firmware Interface/Secure Boot." <https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot>
26. ArchWiki. "Dm-verity." <https://wiki.archlinux.org/title/Dm-verity>
27. systemd.io. "TPM2 PCR Measurements Made by systemd." <https://systemd.io/TPM2_PCR_MEASUREMENTS/>
28. ManKier. "systemd-measure(1)." <https://www.mankier.com/1/systemd-measure>
29. Kernel.org. "dm-verity." <https://docs.kernel.org/admin-guide/device-mapper/verity.html>
30. Kernel.org. "fs-verity: read-only file-based authenticity protection." <https://docs.kernel.org/filesystems/fsverity.html>
31. Starlab. "An Introduction to Dm-verity in Embedded Device Security." <https://www.starlab.io/blog/dm-verity-in-embedded-device-security>

### LSM framework
32. Wikipedia. "Linux Security Modules." <https://en.wikipedia.org/wiki/Linux_Security_Modules>
33. Kernel.org. "LSM BPF Programs." <https://docs.kernel.org/bpf/prog_lsm.html>
34. Kernel.org. "Landlock: unprivileged access control." <https://www.kernel.org/doc/html/latest/userspace-api/landlock.html>
35. Phoronix. "Linux 6.12 Landing Integrity Policy Enforcement (IPE) Module." 2024-09. <https://www.phoronix.com/news/Linux-6.12-IPE-LSM-Security>
36. eBPF.Hamza-Megahed.com. "Linux Security Module (LSM)." <https://ebpf.hamza-megahed.com/docs/chapter5/2-lsm/>
37. Dawid Macek. "eBPF + LSM: Synchronous execution prevention." 2025. <https://www.dawidmacek.com/posts/2025/ebpf-lsm-synchronous-execution-prevention/>
38. Eunomia. "eBPF Tutorial 19: Security Detection and Defense using LSM." <https://eunomia.dev/tutorials/19-lsm-connect/>
39. Kernel newbies. "Linux_6.12." <https://kernelnewbies.org/Linux_6.12>

### Confidential computing & hardware root of trust
40. Microsoft Learn. "Microsoft Pluton security processor." <https://learn.microsoft.com/en-us/windows/security/hardware-security/pluton/microsoft-pluton-security-processor>
41. Microsoft Learn. "Microsoft Pluton as Trusted Platform Module (TPM 2.0)." <https://learn.microsoft.com/en-us/windows/security/hardware-security/pluton/pluton-as-tpm>
42. threatshub.org. "Not everyone's wild about Microsoft's Pluton security chip: PC makers turn it off." 2025.
43. mjg59 (Matthew Garrett). "Pluton is not (currently) a threat to software freedom." <https://mjg59.dreamwidth.org/58125.html>
44. KitGuru. "AMD Ryzen Pro chips with Microsoft Pluton won't boot Linux." <https://www.kitguru.net/components/cpu/joao-silva/amd-ryzen-pro-chips-with-microsoft-pluton-wont-boot-linux/>
45. Kollenda. "General overview of AMD SEV-SNP and Intel TDX." FAU sys, 2022/23. <https://sys.cs.fau.de/extern/lehre/ws22/akss/material/amd-sev-intel-tdx.pdf>
46. ACM SIGMETRICS '25 summer. "Confidential VMs Explained: An Empirical Analysis of AMD SEV-SNP and Intel TDX." DOI 10.1145/3700418. <https://dl.acm.org/doi/10.1145/3700418>
47. Intel. "What's New | Intel Trust Authority." <https://docs.trustauthority.intel.com/main/articles/articles/ita/whats-new.html>
48. Onidel. "AMD SEV-SNP vs Intel TDX on VPS in 2025." <https://onidel.com/blog/amd-sev-snp-vs-intel-tdx-vps>

### CHERI / Morello / Formal Verification
49. University of Cambridge Computer Lab. "CHERI: The Arm Morello Board." <https://www.cl.cam.ac.uk/research/security/ctsrd/cheri/cheri-morello.html>
50. ACM POPL 2025 (PACMPL). "Morello-Cerise: A Proof of Strong Encapsulation for the Arm Morello Capability Hardware Architecture." DOI 10.1145/3729329. <https://dl.acm.org/doi/10.1145/3729329>
51. Cambridge Computer Lab. "CHERI Rigorous Engineering." <https://www.cl.cam.ac.uk/research/security/ctsrd/cheri/cheri-formal.html>
52. Klein, et al. "seL4: Formal Verification of an Operating-System Kernel." SOSP 2009 / CACM 2010. <https://www.sigops.org/s/conferences/sosp/2009/papers/klein-sosp09.pdf>
53. seL4 Foundation. "The seL4 Microkernel whitepaper." <https://sel4.systems/About/seL4-whitepaper.pdf>
54. seL4 Foundation. "seL4 Summit 2025 Abstracts." <https://sel4.systems/Summit/2025/abstracts2025.html>

### Windows-side architecture & Microsoft stack
55. Microsoft Learn. "Memory Integrity and Virtualization-Based Security (VBS)." <https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/device-guard-and-credential-guard>
56. Microsoft Learn. "Credential Guard overview." <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/>
57. Microsoft Learn. "Enable virtualization-based protection of code integrity." <https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity>
58. Thomas Marcussen. "Windows 11 Security Boost – Credential Guard and HVCI Now Default." <https://blog.thomasmarcussen.com/windows-11-security-boost-credential-guard-and-hvci-now-default/>
59. Shlomi Boutnaru. "The Windows Security Journey — HVCI." Medium. <https://medium.com/@boutnaru/the-windows-security-journey-hvci-hypervisor-protected-code-integrity-c13f98cac96f>
60. Tom's Hardware. "How to Disable VBS and Speed Up Windows 11 or 10." <https://www.tomshardware.com/how-to/disable-vbs-windows-11>

### Android Verified Boot
61. Android Open Source Project. "Verified Boot." <https://source.android.com/docs/security/features/verifiedboot>
62. Google AOSP. "Android Verified Boot 2.0." <https://android.googlesource.com/platform/external/avb/+/master/README.md>
63. Kashif Mukhtar. "Security: Titan M2 Hardware Root Of Trust Explained." <https://kashifmukhtar.com/pixel-10-titan-m2-security-hardware-root-trust/>

### Fedora Silverblue / bootc / atomic
64. Fedora Magazine. "Discover Fedora Kinoite: a Silverblue variant..." <https://fedoramagazine.org/discover-fedora-kinoite/>
65. Fedora Magazine. "Introducing Fedora Atomic Desktops." <https://fedoramagazine.org/introducing-fedora-atomic-desktops/>
66. Planet KDE. "What's new for Fedora Atomic Desktops in Fedora 41." 2024-10. <https://planet.kde.org/siosms-blog-2024-10-29-whats-new-for-fedora-atomic-desktops-in-fedora-41/>

### Kernel hardening / signing
67. grsecurity. "Announcement of support timeline." <https://grsecurity.net/>
68. HardenedLinux. "Linux kernel mitigation checklist." <https://hardenedlinux.github.io/system-security/2016/12/13/kernel_mitigation_checklist.html>
69. Red Hat Documentation. "Signing a kernel and modules for Secure Boot (RHEL 9)." <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_monitoring_and_updating_the_kernel/signing-a-kernel-and-modules-for-secure-boot_managing-monitoring-and-updating-the-kernel>
70. Debian Wiki. "SecureBoot." <https://wiki.debian.org/SecureBoot>
71. Ubuntu Wiki. "UEFI/SecureBoot/DKMS." <https://wiki.ubuntu.com/UEFI/SecureBoot/DKMS>

### Compat-layer ecosystem
72. CodeWeavers. "CrossOver 26 Released – Powered By Wine 11.0." 2026. <https://www.codeweavers.com/>
73. Phoronix. "CrossOver 26 Released - Powered By Wine 11.0 For Windows Apps/Games On Linux + macOS." 2026. <https://www.phoronix.com/news/CrossOver-26>
74. Heroic Games Launcher. <https://github.com/Heroic-Games-Launcher/HeroicGamesLauncher>
75. Lutris. "Heroic Games Launcher." <https://lutris.net/games/heroic-games-launcher/>
76. BigGo News. "Bottles Emerges as User-Friendly Alternative to Lutris and Heroic for Running Windows Software on Linux." <https://biggo.com/news/202508120723_Bottles_vs_Lutris_Heroic_Linux_Windows_Software>

### Artificial Immune Systems / bio-inspired
77. ScienceDirect. "Artificial Immune Systems approaches to secure the internet of things." <https://www.sciencedirect.com/science/article/abs/pii/S1084804520300114>
78. Song et al. "SAIS: A Novel Bio-Inspired Artificial Immune System Based on Symbiotic Paradigm." GECCO 2024.
79. Scipublications. "Artificial Immune Systems: A Bio-Inspired Paradigm for Computational Intelligence." 2024.

### One-shot signatures (closest quantum-crypto analog to APE)
80. btq.com. "One-Shot Signatures: A New Paradigm in Quantum Cryptography." <https://www.btq.com/blog/one-shot-signatures-new-paradigm-in-quantum-cryptography>
81. eprint.iacr.org/2020/107. "One-shot Signatures and Applications to Hybrid Quantum/Classical Authentication."
82. eprint.iacr.org/2025/486. "On One-Shot Signatures, Quantum vs Classical Binding."

### Genode / microkernel
83. L4 family Wikipedia. <https://en.wikipedia.org/wiki/L4_microkernel_family>
84. OSnews. "Bringing Genode to the OKL4 Kernel." <https://www.osnews.com/story/21440/bringing-genode-to-the-okl4-kernel/>

---

## 12. Deliverables for S74 Agent J

- This document: `docs/research/s74_j_moat_landscape.md`
- 84 citations (goal was 30+)
- One-table positioning (§8)
- 5 moat-widening proposals (§5) with LOC + session estimates
- 3 explicit rejects (§6) to prevent drift
- Peer-review simulation (§7) for paper-strategy planning
- Open-question list (§10) for future audit agents

**Top 3 findings (honest peer-review):**

1. **The strongest claim that would survive peer review:** The
   Authority Proof Engine (APE) with self-consuming proofs, the 23-pair
   chromosomal authority struct, and the 6-family dispatchable trust
   RISC ISA are three genuinely novel primitives not reproduced
   anywhere in the 2024-2026 literature we surveyed (LSMs, TPM, CHERI,
   seL4, VBS/HVCI, SEV/TDX, Pluton). The self-consuming-proof shape has
   a quantum-crypto cousin (one-shot signatures — BTQ, eprint 2025/486)
   but ours is classical and ships in a Linux kernel module today. This
   is the short-paper thesis.

2. **The claim that would NOT survive peer review:** "Runs Windows
   drivers under hardware-rooted authority." Our wdm_host.ko is a
   30-40% skeleton; ReactOS has been grinding on the same tier-3
   problem for 30 years and is still alpha. Any real .sys driver would
   oops. The academic honest claim is "we have a gated refusal
   mechanism that declines all .sys loads by default, safer than Wine
   which refuses categorically without a gate." Keep tier-3 in the
   product story, NOT in the academic submission.

3. **The single biggest gap between self-perception and defensible
   reality**: the seven theorems have never been adversarially
   exercised. The sysfs counters sit at 0 under clean workloads; no
   red-team has tried to violate T2 (replay), T4 (inheritance bound),
   or T6 (metabolic fairness). A 1-2 session adversarial harness
   (Proposal A in §5) would close this gap completely and is the
   highest-ROI thing on the S75 roadmap.

**Top 3 actions to widen moat (recommended for S75 if not S74):**

1. Adversarial theorem harness (Proposal A, 1-2 sessions, ~800 LOC) —
   takes the paper from "asserted" to "demonstrated".
2. libtrust_wine_shim (Proposal B, 2-3 sessions, ~1200 LOC) — turns
   Wine's coverage advantage into OUR coverage advantage by gating
   every NT syscall under our authority model. Only we can do this.
3. Self-attestation quine (Proposal C, 1 session, ~250 LOC) — closes
   the S73-F gap; gives us live-reflexivity that even Windows HVCI
   doesn't have.

All three are:
- In range of our unique substrate (APE, kernel module, trust ISA).
- NOT things any competitor is trying to do.
- Technically feasible within S75 scope (1-6 sessions total, ~2250 LOC).
- Peer-reviewable outcomes.

---

## Sources

- [GitHub: vkd3d-proton](https://github.com/HansKristian-Work/vkd3d-proton)
- [Proton: Valve Takes Another Huge Step Forward With Wine 11 Integration! (thegeek.games)](https://thegeek.games/2026/04/19/proton-valve-takes-another-huge-step-forward-with-wine-11-integration/)
- [Valve Quietly Rebased Proton on Wine 11 (WCCFTech)](https://wccftech.com/valve-quietly-rebased-proton-on-wine-11-and-linux-gaming-just-got-windows-level-frame-pacing/)
- [Wikipedia: Proton (software)](https://en.wikipedia.org/wiki/Proton_(software))
- [Wine 11 Rewrites How Linux Runs Windows Games at Kernel Level (XDA)](https://www.xda-developers.com/wine-11-rewrites-linux-runs-windows-games-speed-gains/)
- [Wine 10.15 To Feature Initial Support For Using NTSYNC On Linux (Phoronix)](https://www.phoronix.com/news/Wine-10.15-With-NTSYNC)
- [Are We Anti-Cheat Yet?](https://areweanticheatyet.com/)
- [Wikipedia: SteamOS](https://en.wikipedia.org/wiki/SteamOS)
- [Valve Says SteamOS 3.0 Will Be Available for Everyone (9to5Linux)](https://9to5linux.com/valve-says-steamos-3-0-will-be-available-for-everyone-to-download-and-install)
- [Linux ecosystem contributions from SteamOS (LWN)](https://lwn.net/Articles/946188/)
- [ReactOS 0.4.15 released (ReactOS Project)](https://reactos.org/project-news/reactos-0415-released/)
- [ReactOS 0.4.15 Released (Phoronix)](https://www.phoronix.com/news/ReactOS-0.4.15-Released)
- [ReactOS emits release 0.4.15 (The Register)](https://www.theregister.com/2025/03/25/reactos_drops_release_0415/)
- [Qubes OS: Standalones and HVMs](https://doc.qubes-os.org/en/latest/user/advanced-topics/standalones-and-hvms.html)
- [Qubes OS: Qubes Windows Tools](https://doc.qubes-os.org/en/latest/user/templates/windows/qubes-windows-tools.html)
- [Qubes OS: How to install Windows qubes](https://doc.qubes-os.org/en/latest/user/templates/windows/qubes-windows.html)
- [StationX: Whonix vs Tails (2026)](https://www.stationx.net/whonix-vs-tails/)
- [StateOfSurveillance: Privacy Live Distros](https://stateofsurveillance.org/guides/advanced/privacy-live-distros-comparison/)
- [ArchWiki: TPM](https://wiki.archlinux.org/title/Trusted_Platform_Module)
- [ArchWiki: Dm-verity](https://wiki.archlinux.org/title/Dm-verity)
- [systemd.io: TPM2 PCR Measurements Made by systemd](https://systemd.io/TPM2_PCR_MEASUREMENTS/)
- [Kernel.org: dm-verity](https://docs.kernel.org/admin-guide/device-mapper/verity.html)
- [Kernel.org: fs-verity](https://docs.kernel.org/filesystems/fsverity.html)
- [Kernel.org: LSM BPF Programs](https://docs.kernel.org/bpf/prog_lsm.html)
- [Kernel.org: Landlock](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html)
- [Phoronix: Linux 6.12 IPE LSM](https://www.phoronix.com/news/Linux-6.12-IPE-LSM-Security)
- [Wikipedia: Linux Security Modules](https://en.wikipedia.org/wiki/Linux_Security_Modules)
- [Microsoft Learn: Pluton security processor](https://learn.microsoft.com/en-us/windows/security/hardware-security/pluton/microsoft-pluton-security-processor)
- [Microsoft Learn: Pluton as TPM](https://learn.microsoft.com/en-us/windows/security/hardware-security/pluton/pluton-as-tpm)
- [mjg59: Pluton is not (currently) a threat to software freedom](https://mjg59.dreamwidth.org/58125.html)
- [KitGuru: AMD Ryzen Pro chips with Microsoft Pluton won't boot Linux](https://www.kitguru.net/components/cpu/joao-silva/amd-ryzen-pro-chips-with-microsoft-pluton-wont-boot-linux/)
- [ACM: Confidential VMs Explained (SEV-SNP vs TDX)](https://dl.acm.org/doi/10.1145/3700418)
- [Cambridge CL: CHERI/Morello](https://www.cl.cam.ac.uk/research/security/ctsrd/cheri/cheri-morello.html)
- [ACM POPL: Morello-Cerise](https://dl.acm.org/doi/10.1145/3729329)
- [seL4: Formal Verification SOSP 2009](https://www.sigops.org/s/conferences/sosp/2009/papers/klein-sosp09.pdf)
- [seL4 Foundation: whitepaper](https://sel4.systems/About/seL4-whitepaper.pdf)
- [seL4 Summit 2025 Abstracts](https://sel4.systems/Summit/2025/abstracts2025.html)
- [Microsoft Learn: VBS / Memory Integrity](https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/device-guard-and-credential-guard)
- [Microsoft Learn: Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [AOSP: Verified Boot](https://source.android.com/docs/security/features/verifiedboot)
- [Google AOSP: AVB 2.0](https://android.googlesource.com/platform/external/avb/+/master/README.md)
- [Titan M2 explained (Kashif Mukhtar)](https://kashifmukhtar.com/pixel-10-titan-m2-security-hardware-root-trust/)
- [Fedora Magazine: Kinoite](https://fedoramagazine.org/discover-fedora-kinoite/)
- [Fedora Magazine: Atomic Desktops](https://fedoramagazine.org/introducing-fedora-atomic-desktops/)
- [grsecurity](https://grsecurity.net/)
- [CodeWeavers: CrossOver](https://www.codeweavers.com/)
- [Phoronix: CrossOver 26 Released](https://www.phoronix.com/news/CrossOver-26)
- [BTQ: One-Shot Signatures](https://www.btq.com/blog/one-shot-signatures-new-paradigm-in-quantum-cryptography)
- [eprint.iacr.org/2020/107: One-shot Signatures and Applications](https://eprint.iacr.org/2020/107)
- [eprint.iacr.org/2025/486: On One-Shot Signatures](https://eprint.iacr.org/2025/486.pdf)
- [ScienceDirect: AIS approaches to IoT security](https://www.sciencedirect.com/science/article/abs/pii/S1084804520300114)
- [ACM SIGMETRICS 2025: Confidential VMs](https://dl.acm.org/doi/10.1145/3726854.3727280)
- [L4 Microkernel Family (Wikipedia)](https://en.wikipedia.org/wiki/L4_microkernel_family)
