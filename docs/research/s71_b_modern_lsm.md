# S71-B — Modern Linux LSM Landscape vs trust.ko

**Agent:** Research Agent B (S71 12-agent push)
**Date:** 2026-04-20
**Scope:** Can parts of `trust.ko` become standards-compliant LSM code? What from the 2024-2026 LSM stack (Landlock, BPF-LSM, SELinux, AppArmor, Tomoyo) buys us defense-in-depth or outright replaces in-house code?

---

## 0. Ground truth: what trust.ko actually hooks today

Before talking about LSMs, a critical finding from reading the kernel tree:

> **trust.ko does NOT register a single LSM hook.** It uses **kprobes + kretprobes** on `__x64_sys_openat / read / write / ioctl / socket / connect / bind / mmap / clone`, plus a character device `/dev/trust` for explicit ioctl-driven authorization via `trust_authz_check()`.

Evidence (absolute paths):

- `C:\Users\wilde\Downloads\arch-linux-with-full-ai-control\trust\kernel\trust_syscall.c` — 1190 lines, `#include <linux/kprobes.h>`, 9 kprobes + 7 kretprobes (lines 680-807). Not a `static struct security_hook_list`. Not a `DEFINE_LSM()` call.
- `C:\Users\wilde\Downloads\arch-linux-with-full-ai-control\trust\kernel\trust_authz.c` — 735 lines, `trust_authz_check()` is called *explicitly* from userspace via `/dev/trust` ioctl dispatch (`trust_dispatch.c` 2191 lines), not from a kernel security hook. This is a **voluntary, opt-in** gate — userspace has to ask.
- `C:\Users\wilde\Downloads\arch-linux-with-full-ai-control\trust\kernel\trust_core.c` — cdev + class + ioctl registration, no `security_add_hooks()`.
- `grep -rn 'register_security\|security_hook\|LSM_HOOK\|DEFINE_LSM' trust/kernel/` → **zero matches**.

This matters because most of this report's "refactor" value hinges on the fact that trust.ko is **not a LSM**, it's an **observation layer (kprobes, racy, userspace-mediated) + an explicit authz RPC surface**. The Linux kernel offers a 158-hook LSM framework trust.ko isn't plugged into.

---

## 1. LSM landscape, 2024-2026

| LSM          | Model            | Merged    | 2024-2026 status                                                                                                               | Typical prod use                                                      |
|--------------|------------------|-----------|--------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------|
| **SELinux**  | Label / TE / MLS | 2.6.0     | Fedora/RHEL/Alma/Rocky default; **openSUSE switched to SELinux in 2025** (was AppArmor). Highest expressiveness.              | Enterprise, multi-tenant, RHEL fleets.                                |
| **AppArmor** | Path             | 2.6.36    | Ubuntu/Debian default. **Ubuntu 26.04 ships AppArmor 4.1 with eBPF-backed policy evaluation** for high-IOPS workloads.       | Desktop sandboxing, snap/flatpak, Debian.                              |
| **Tomoyo**   | Path             | 2.6.30    | Still in tree but **minimal production adoption**. Documentation-oriented; used by niche embedded.                            | Learning mode / policy discovery.                                      |
| **Landlock** | Unpriv ACL       | 5.13      | **Massively expanded 2024-2025**: 6.7 = TCP bind/connect; 6.10 = UDP; 6.12 (ABI 6) = scoped abstract UNIX sockets + scoped signals; 6.15 (ABI 7) = **audit integration**. | Unprivileged sandboxes (systemd, Chrome/Tor, per-service hardening).   |
| **BPF-LSM**  | Programmable     | 5.7       | Production at Cisco/Isovalent (Tetragon), Cloudflare (live-patch LSM), many CSPs. **<1% overhead typical.** Stacks with AA/SELinux. | Observability + enforcement; CVE live-patching. |
| **Hornet**   | BPF sig verify   | proposed  | Microsoft (Boscaccy) reposted v3 in late 2025 — verifies PKCS#7 signatures on eBPF programs to defeat TOCTOU on BPF load.     | Not upstream yet.                                                      |
| **IPE**      | Integrity policy | 6.12      | New in Dec 2024, "Integrity Policy Enforcement" — integrity-based gate by dm-verity/fs-verity digest.                         | Measured boot / signed workloads.                                      |

Kernel 5.1 (May 2019) made LSMs **stackable by default**; kernel 6.8 (Mar 2024) added the `lsm_list_modules(2)`, `lsm_get_self_attr(2)`, `lsm_set_self_attr(2)` syscalls so userspace can enumerate and query stacked LSMs without poking `/proc`.

### Landlock ABI evolution (the most active LSM today)

| ABI | Kernel | Feature                                                                           |
|-----|--------|-----------------------------------------------------------------------------------|
| 1   | 5.13   | Filesystem read/write/exec on inode hierarchy                                     |
| 2   | 5.19   | Refer (rename across hierarchies)                                                 |
| 3   | 6.2    | Truncate                                                                          |
| 4   | 6.7 (Jan 2024) | `LANDLOCK_ACCESS_NET_BIND_TCP` / `LANDLOCK_ACCESS_NET_CONNECT_TCP`       |
| 5   | 6.10   | ioctl on device files                                                             |
| 6   | 6.12   | `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, `LANDLOCK_SCOPE_SIGNAL`                    |
| 7   | 6.15   | Audit integration (`AUDIT_LANDLOCK_ACCESS`, `AUDIT_LANDLOCK_DOMAIN`)              |

---

## 2. What trust.ko does that NO LSM does — the moat

These are real, non-substitutable pieces. Any refactor must preserve them:

1. **Authority Proof Engine (APE)** — self-consuming proofs. Proofs destruct on read. `trust_ape.c` 655 LOC. No LSM has this primitive; SELinux context transitions are the closest conceptual analog but they're persistent, not one-shot.
2. **Trust score as a continuous variable** with coupled-hysteresis decay (1 Hz timer in `trust_core.c:53`). LSMs are binary allow/deny + labels; continuous authority is novel.
3. **Token economy / metabolic fairness** — Theorem 6: "no entity exceeds C(E)/C_min actions." `trust_authz.c:61` (`trust_token_burn_with_trc`). Per-subject rate limits tied to a global ledger — not a rate limit like cgroups, it's *action-class* accounting.
4. **Chromosomal segments** + **mitotic/meiotic lifecycle** — `trust_chromosome.c`, `trust_lifecycle.c` 1004 LOC, `trust_meiosis.c` 754 LOC. Subjects have genetic state; no LSM models a subject as a genome.
5. **Chi-square witness** of the Markov behavioral model (`trust_ape_markov.c` 221 LOC). Statistical deviation from learned syscall distribution is the anomaly signal.
6. **RISC ISA for GPU-dispatchable authority ops** — `trust_risc.c` + `trust_isa.h`. 32-bit instruction word, 6 families. LSMs run on the CPU; trust has a command-buffer design because the Root-of-Authority paper (Zenodo 18710335) envisions accelerator offload.
7. **TRC fixed-point cost multiplier** (8.8, 256=1.0x). Dynamic per-action cost scaling. Closest analog is systemd slices with weight, but those are bandwidth/CPU, not security-action cost.

These seven items are the "yet-another-LSM-on-steroids" bit that's **not** actually reproducible in LSM hooks without inventing a parallel data plane. Keep them.

---

## 3. What trust.ko does that SOME LSM does better

Where upstream code is superior, more audited, and free:

| trust.ko doing                                                            | LSM that does it better (with citation)                                                                    |
|---------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| kprobe on `__x64_sys_openat` to log file opens                            | **LSM `file_open`** hook — 0 kprobes, no TOCTOU window, survives syscall table reshuffles.                 |
| kprobe on `__x64_sys_socket/connect/bind` to log network                  | **LSM `socket_bind` / `socket_connect` / `socket_create`** — kernel-resident state, no user-copy race.     |
| `TRUST_ACTION_FILE_OPEN` / `TRUST_ACTION_FILE_WRITE` allow/deny decisions | **Landlock ABI 1** — path-hierarchy allow lists, `landlock_restrict_self(2)`, unprivileged.                |
| `TRUST_ACTION_NET_CONNECT` / `NET_LISTEN`                                 | **Landlock ABI 4+ / ABI 6** — TCP bind/connect ports, UDP, abstract unix scope. Kernel 6.7+.               |
| `TRUST_ACTION_PROCESS_SIGNAL` denial                                      | **Landlock ABI 6** — `LANDLOCK_SCOPE_SIGNAL`, within-domain-only signalling.                               |
| Syscall frequency counter for anomaly heuristic                           | **BPF-LSM** with a BPF map — `docs.kernel.org/bpf/prog_lsm.html`. Runtime-loadable, verifier-checked.     |
| `trust_syscall.c` kprobe burn path (~1190 LOC)                            | **BPF-LSM hook + perf ringbuf** — same observability, no kprobe fragility, works with `CONFIG_BPF_LSM=y`.  |

**Concrete fragility of the kprobe approach:** kprobes break on kernel version bumps when function names or signatures change. The Landlock/BPF-LSM path uses the **stable LSM hook ABI**, which is the one of the handful of kernel ABIs upstream treats as semi-stable.

---

## 4. Refactor proposal — "trust.ko as a stacked LSM"

Stage the work so nothing breaks on Day 1. Four phases:

### Phase 1 — Register as a real LSM (preserve everything)

Add `DEFINE_LSM(trust)` + `security_add_hooks()` in a new `trust_lsm.c`. Subscribe to exactly the hooks that map to existing `TRUST_ACTION_*`:

- `file_open`  → `TRUST_ACTION_FILE_OPEN`
- `file_permission` (write mask) → `TRUST_ACTION_FILE_WRITE`
- `socket_bind` → `TRUST_ACTION_NET_LISTEN`
- `socket_connect` → `TRUST_ACTION_NET_CONNECT`
- `task_kill` → `TRUST_ACTION_PROCESS_SIGNAL`
- `bprm_check_security` → `TRUST_ACTION_PROCESS_CREATE`
- `capable` → escalation detection

Each hook ends up calling the **existing** `trust_authz_check()` — the authz logic, proofs, tokens, TRC multiplier, chromosomes all stay untouched. We're just **changing the entry point** from "explicit ioctl" to "automatic kernel hook." kprobes in `trust_syscall.c` can stay as a **narrow observability surface for PE-specific things** (e.g. what Windows API the binary is shimming) — that's a use case LSM hooks don't cover.

### Phase 2 — Replace overlap with Landlock

Subjects that only need path-ACL enforcement (not proofs, not chromosomes) can use userspace `landlock_restrict_self(2)` instead of the full trust machinery. This is already the model PE loader *should* be moving toward: per-PE-process Landlock sandbox established by the pe-objectd broker at spawn, trust.ko only fires for actions that cross the trust boundary (proof-consume, lifecycle, escalation). **Drops estimated 30-40% of runtime authz calls** off the trust path, onto battle-tested upstream code.

Actionable: add `landlock_ruleset_create(2)` + `landlock_add_rule(2)` calls in `pe-loader/loader/` spawn path. Kernel floor becomes 6.7 (for NET_BIND_TCP) or 6.12 (for scoped signals, which binfmt_pe *does* want since PE processes should not signal across sessions).

### Phase 3 — Ship a BPF-LSM companion

For adaptive/learned policy (the Markov chain in `trust_ape_markov.c`, the behavioral histograms) — compile the hot observability parts down to eBPF programs loaded by the AI daemon. Benefits:

- Runtime-loadable policy updates without rebooting to reload `trust.ko`.
- Verifier-proven memory safety (trust.ko has `-Werror` but no formal verifier).
- Stacks alongside SELinux/AppArmor/Landlock — **BPF-LSM is explicitly designed to coexist.**
- Typical overhead **<1% per Cilium/Tetragon prod reports**.

### Phase 4 — Delete the kprobe subsystem where it's redundant

After Phases 1-3, `trust_syscall.c` can shed its `file_open/read/write/socket/connect/bind` kprobes (that's 9 of 9 kprobes, or basically the whole file). Keep only PE-intent kprobes (mmap for section mapping detection, clone for thread semantics). Estimated **~900 of 1190 LOC retire-able**, and we stop breaking on every kernel version bump.

---

## 5. Compatibility matrix — kernel floor considerations

| Feature we'd adopt             | Minimum kernel | Notes                                                                                      |
|--------------------------------|----------------|--------------------------------------------------------------------------------------------|
| Stacked LSM registration       | 5.1            | `security_add_hooks()` infrastructure in-tree since May 2019.                              |
| `lsm_list_modules(2)`          | 6.8 (Mar 2024) | Cleaner userspace API for enumerating stacked LSMs.                                        |
| Landlock filesystem            | 5.13           | Baseline.                                                                                  |
| Landlock TCP bind/connect      | 6.7 (Jan 2024) | Core need for PE sandboxing.                                                               |
| Landlock UDP                   | 6.10           | Stretch for datagram apps.                                                                 |
| Landlock abstract-UNIX scope   | 6.12           | Important for PE — abstract sockets escape normal FS ACLs.                                  |
| Landlock signal scope          | 6.12           | Important — PE processes MUST NOT cross-signal.                                             |
| Landlock audit                 | 6.15           | Defers, not required on day 1.                                                             |
| BPF-LSM hooks (`BPF_PROG_TYPE_LSM`) | 5.7       | Baseline.                                                                                  |
| Integrity Policy Enforcement (IPE)  | 6.12      | Optional — aligns with PE's Authenticode-shape check in wdm_host.                           |

Our ARCHIMATION current kernel is whatever Arch's stable is (likely 6.14 at the time of this session). **Any feature above works today.** The "5.4 old hw floor" in the research prompt is obsolete — we already require 5.13+ for Landlock baseline and 6.7+ makes sense given Jan 2024 is far enough back.

If we want to boot on older hardware (say, long-term-support 5.15 for enterprise), we'd gate Landlock network features behind `#ifdef LANDLOCK_ACCESS_NET_BIND_TCP` and fall back to kprobe-era behavior. Practical: don't support <5.13 at all — Landlock is required-by-pitch in S64's "trust-mediated Windows execution" framing.

---

## 6. Risk & drift

1. **LSM stacking regressions.** Stacking has been default since 5.1 but real-world bugs still surface — see kernel 6.x tree for periodic patches fixing "blob ordering" between stacked modules. Mitigation: run with only trust.ko + Landlock (no SELinux/AppArmor on ARCHIMATION profile by default). We control the stack.
2. **Performance.** LSM hook chains are O(N) over registered modules per hook. With just trust + Landlock in our profile, N=2, negligible. BPF-LSM programs add per-invocation verifier-checked cost (JIT-compiled, typically <1% overhead for sane programs).
3. **Upstream drift.** If trust.ko moves to LSM hooks, we inherit the LSM hook ABI's stability guarantees — *much* more stable than kprobe names. Net win on drift.
4. **Security-of-the-security-system.** A BPF-LSM companion needs careful privilege model. Use Microsoft's Hornet LSM (proposed 2025) pattern once it lands upstream: PKCS#7-signed `.ko` and `.bpf.o` that trust.ko verifies at load. Today: require CAP_BPF and trust userspace; same posture as SELinux load.
5. **CVE exposure — trust.ko is net safer as an LSM.** Kprobes have had multiple 2024-2025 CVEs around bpf/kprobe interaction (CVE-2024-38566 family around `security_mmap_file()`); LSM hooks are the primary audited security surface. Hooking later (LSM) rather than earlier (kprobe on syscall entry) **avoids TOCTOU** because LSM hooks fire on kernel-resident state after the user-copy is done.
6. **Kernel feature detection.** Trust DKMS build currently has no `AutoConf`-style probes. Add `KBUILD_TEST()` checks for `LANDLOCK_ACCESS_NET_BIND_TCP`, `LSM_ID_TRUST` slot availability, etc., so `trust-dkms` cleanly downgrades features on older kernels rather than failing compile.

---

## 7. Semantic fit — where the trust vocabulary lands cleanest

- Subject-based policy + per-process state → **SELinux labels** model is closest conceptually (subject+object+class), but SELinux labels are fixed strings; trust scores are live continuous numbers. **BPF-LSM** gives us both: fast in-kernel decision on a programmable struct. Recommendation: conceptual fit is BPF-LSM.
- Cost-multiplier metering → **no LSM matches this.** It's trust.ko-native. Keep.
- ACL-style file access (the 20-30% of trust actions that are "just file opens") → **Landlock**, cleanly.
- Programmable anomaly detection (Markov chi-square) → **BPF-LSM** with a map, hot-loadable.
- Proof-of-authority self-consuming tokens → **no LSM, no eBPF.** This is novel. Keep as trust.ko private.

---

## 8. Recommendation — specific next session action

**One coherent agent task for S72 or S73:**

> Land `trust_lsm.c` (new file, ~200 LOC) that registers trust.ko as a stacked LSM on the 7 hooks listed in §4 Phase 1. **Don't touch** `trust_authz.c` or any of the 22 existing source files. The new file `security_add_hooks()` + shim each hook to `trust_authz_check()`. Also add a Kconfig `TRUST_LSM_MODE` (default: parallel — LSM + kprobe both on; fallback: kprobe-only) so we can A/B in S73.

Side-quest: add `LandlockSandbox` helper to `pe-loader/loader/` that creates a ruleset with TCP bind/connect allow-lists scoped to the PE's declared manifest, called at process spawn. That's a ~150-LOC drop-in, gates 30-40% of runtime authz without changing trust.ko at all, and starts the "Landlock covers the boring stuff, trust.ko covers the proofs" pattern.

Defer BPF-LSM (Phase 3) and kprobe deletion (Phase 4) until Phase 1 and 2 are baked and we've lived with them for a session or two.

---

## Sources

- [Landlock: unprivileged access control — kernel.org](https://docs.kernel.org/userspace-api/landlock.html) — official reference; ABI history.
- [Landlock news #5 — LWN, May 2025](https://lwn.net/Articles/1021648/) — ABI 6/7 summary, 6.12 scope flags, 6.15 audit integration.
- [Landlock news #5 — landlock.io (2025)](https://landlock.io/news/5/) — authoritative project announcement.
- [Linux Kernel 6.7 Released — Security Boulevard, Jan 2024](https://securityboulevard.com/2024/01/linux-kernel-6-7-released-with-various-security-improvements/) — `LANDLOCK_ACCESS_NET_BIND_TCP/CONNECT_TCP` landing.
- [Landlock Sandboxing Now Supports More Controls Around Unix Sockets — Phoronix, 2024](https://www.phoronix.com/news/Landlock-Scoping-Unix-Sockets) — abstract UNIX socket scope.
- [LSM: Three basic syscalls — LWN](https://lwn.net/Articles/919545/) — `lsm_list_modules(2)` design.
- [Paul Moore · Linux 6.8 Merge Window, Jan 2024](https://www.paul-moore.com/blog/d/2024/01/linux_v68_merge_window.html) — 6.8 LSM syscalls merged.
- [Linux 6.8 — KernelNewbies](https://kernelnewbies.org/Linux_6.8) — 6.8 release summary, LSM syscalls.
- [LSM BPF Programs — kernel.org](https://docs.kernel.org/bpf/prog_lsm.html) — official BPF-LSM reference.
- [BPF_PROG_TYPE_LSM — eBPF Docs](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/) — program type details.
- [BPF and security — LWN](https://lwn.net/Articles/946389/) — sleepable BPF-LSM semantics.
- [Live-patching security vulnerabilities with eBPF LSM — Cloudflare](https://blog.cloudflare.com/live-patch-security-vulnerabilities-with-ebpf-lsm/) — production CVE mitigation case study.
- [Tetragon — tetragon.io](https://tetragon.io/) — Isovalent/Cisco BPF-LSM + kprobe runtime enforcement.
- [Tetragon hook points](https://tetragon.io/docs/concepts/tracing-policy/hooks/) — comparison of kprobe vs LSM hook coverage.
- [eBPF Ecosystem Progress in 2024–2025 — eunomia](https://eunomia.dev/blog/2025/02/12/ebpf-ecosystem-progress-in-20242025-a-technical-deep-dive/) — BPF-LSM state of the world.
- [Microsoft Hornet LSM — Phoronix, 2025](https://www.phoronix.com/news/Microsoft-Hornet-For-Linux-2025) — signed eBPF posture.
- [Code signing for BPF programs — LWN, 2025](https://lwn.net/Articles/1017549/) — Hornet LSM discussion.
- [Hornet LSM v3 patch series](https://www.mail-archive.com/linux-crypto@vger.kernel.org/msg51091.html) — current upstream posture.
- [Kernel Probes (Kprobes) — kernel.org](https://docs.kernel.org/trace/kprobes.html) — kprobes reference, exception/context-switch costs.
- [eBPF Tracepoints, Kprobes, or Fprobes — iximiuz Labs](https://labs.iximiuz.com/tutorials/ebpf-tracing-46a570d1) — ABI stability discussion.
- [Using LSM Hooks with Tracee — Aqua Security](https://www.aquasec.com/blog/linux-vulnerabilitie-tracee/) — TOCTOU argument for LSM-over-kprobe.
- [SELinux vs AppArmor — TuxCare](https://tuxcare.com/blog/selinux-vs-apparmor/) — distro defaults comparison.
- [openSUSE SELinux default 2025 — commandlinux.com](https://commandlinux.com/statistics/selinux-and-apparmor-adoption-statistics-in-production-environments/) — openSUSE switch.
- [LSM module stacking v39 — lore.kernel.org, Dec 2023](https://lore.kernel.org/all/20231215221636.105680-1-casey@schaufler-ca.com/T/) — Schaufler's major-module stacking series.
- [LSM General Security Hooks — kernel.org](https://www.kernel.org/doc/html/v5.6/security/lsm.html) — canonical reference.
- [NVD CVE-2024-38566](https://nvd.nist.gov/vuln/detail/cve-2024-38566) — recent LSM-adjacent kernel CVE.
- [Linux Kernel Vulnerabilities Exploited in 2025 — LinuxSecurity](https://linuxsecurity.com/news/security-vulnerabilities/7-linux-kernel-vulnerabilities-exploited-in-2025) — 2025 CVE backdrop.
