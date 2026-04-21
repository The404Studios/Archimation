# S71-A: eBPF Observability as a Supplement to `trust.ko`

**Research agent:** A (of 12).
**Date:** 2026-04-20.
**Scope:** Can eBPF take over the observation workload that `trust.ko` currently carries via kprobes + netlink, leaving the kernel module as an *authority-only* surface?
**Verdict:** **Yes, and it is the single highest-leverage reduction of kernel-attack-surface available to this project. Recommend a `trust-bpf` sidecar using libbpf-rs on 5.10+ kernels, falling back to bpftrace/kprobe on <5.10.**

---

## 0. Why this research matters for ARCHWINDOWS

The current `trust.ko` (22 `.c` files, Session 59 manifest GUARD verified 22 sources ship) mixes three concerns in one kernel object:

| Concern | Current location | Can move to eBPF? |
|---|---|---|
| **Authority root** (proofs, token burn, chromosome mutation) | `trust.ko` | **No — stays.** |
| **Syscall observation** (per-PID ring, category filter, netlink fanout) | `trust_syscall.c` (kprobes on `__x64_sys_openat`/`read`/`write`/`ioctl`/`socket`/`connect`/`bind`/`mmap`/`clone`) | **Yes.** |
| **Policy decision dispatch** (TRC cost, FBC repartition) | `trust_dispatch.c`, `trust_fbc.c` | Partial — decisions stay; signal path can be eBPF. |

`trust_syscall.c` today is roughly 1400 LOC of hand-written `kprobe_pre_handler` boilerplate plus netlink fan-out. That is the code I propose to gradually retire. Every line removed from a kernel module is a line the verifier would otherwise have to trust blindly.

The 2024–2025 ecosystem has matured to the point where this kind of move is no longer speculative — Cilium/Tetragon, Falco, and Parca all ship in-kernel eBPF as the mainline observation path. We would be joining, not pioneering, that pattern.

---

## 1. Current state of eBPF (2024–2026)

### 1.1 Feature timeline (verified kernel versions)

The following table is cross-checked against `iovisor/bcc`'s `kernel-versions.md` and the eunomia 2024–2025 deep-dive.

| Feature | Kernel | Year | Relevance to us |
|---|---|---|---|
| BTF (BPF Type Format) | 4.18 | 2018 | Prerequisite for CO-RE. |
| CO-RE via `libbpf` | 5.4 (BTF in kernel) | 2020 | "Compile once, run everywhere" — we need this for a single `.bpf.o` that runs on 5.4–6.18. |
| `BPF_PROG_TYPE_TRACING` (fentry/fexit) | 5.5 | 2020 | ~10× lower overhead than kprobe; requires BTF. |
| `BPF_PROG_TYPE_LSM` | 5.7 | 2020 | Authoritative security hooks — our enforcement lever. |
| Ring buffer (`BPF_MAP_TYPE_RINGBUF`) | 5.8 | 2020 | Replaces perf ring; what our netlink fan-out should become. |
| Sleepable BPF programs | 5.10 | 2020 | Lets LSM handlers call things like `bpf_copy_from_user`. |
| `bpf_timer` | 5.15 | 2021 | Lets us move periodic decay/regen ticks out of `trust_decay_timer_fn`. |
| BPF exceptions (`bpf_assert`) | 6.7 | 2024 | Simpler verifier-friendly assertions. |
| BPF tokens (unpriv delegation) | 6.9 | 2024 | Cleaner privilege model than CAP_BPF blanket. |
| **BPF arena** (up-to-4 GB sparse shared memory) | **6.9** | 2024 | Zero-copy kernel↔userspace large data exchange. Verified: merged by Alexei Starovoitov in the 6.9 merge window (Cilium/Isovalent confirm). |
| Event suppression on perf/ringbuf | 6.10 | 2024 | In-kernel filtering at the source. |
| **`sched_ext`** (eBPF CPU scheduler) | **6.12** | 2024 | Meta + Google ship in production. Fedora ARK enables by default. |
| Sched_ext fault-recovery improvements | 6.19 | 2025 | ~15% latency boost in the published benchmark; graceful fallback when eBPF scheduler faults. |

Arch Linux's 2026 releases ship on `linux-lts 6.18.22-1` (January 2026 ISO, `9to5linux.com/arch-linux-kicks-off-2026...`). Rolling-release users are at 6.18+ by default. That means **every ARCHWINDOWS installation targeted at 2026 hardware has BPF arena, sched_ext, and signed-BPF-adjacent infrastructure available.** We are not constrained by old kernels on the baseline target.

### 1.2 Verifier hardening and CVE posture (2024–2025)

The verifier has been the long-running weak point. Recent posture:

- **No major eBPF CVEs in the wild in 2024** (per eunomia's 2024–2025 ecosystem review) — this reflects reviewer saturation, not an invulnerable verifier.
- `CVE-2024-42075` — BPF arena memory safety patch, fixed in 6.9.x stable.
- `CVE-2024-56614` / `CVE-2024-56615` — PoCs released, both patched. NCC Group's 2024 audit surfaced scalar-tracking bugs that let bit-twiddling trick the verifier's range analysis; follow-up fixes have been merged through 6.8–6.10.
- Academic: `25Oakland.pdf` — "SoK: Challenges and Paths Toward Memory Safety for eBPF" (Kaiming Huang, 2025) argues for formal verification of the verifier itself; work in progress.

**Design consequence.** If we load eBPF programs at boot as root (which we do — `ai-control.service` is `User=root`), we are in the same trust domain the attacker would be exploiting *from*, so the CVE surface is "kernel escalation from root" which is less alarming than the unprivileged-escape class. Still, the lesson is:

- Keep eBPF programs **narrow** (fewer loops, fewer helpers).
- Sign them once two-phase signing (per Boscaccy/Wang, bpfconf 2025) lands upstream.
- Treat eBPF attachment the same way we treat kernel module loading: through the authority chain in `trust.ko`.

### 1.3 What does each production project actually use?

| Project | Kernel floor | Attachment | Userspace | Notes |
|---|---|---|---|---|
| **Cilium / Tetragon 1.x** | 4.19 (tested 4.19/5.4/5.10/5.15/bpf-next) | kprobe + LSM + tracepoint | Go, `cilium/ebpf` lib | 1.68% overhead on kernel build workload. |
| **Falco modern-bpf** | 5.8 recommended | CO-RE ringbuf | C++ `libscap` | Legacy eBPF driver deprecated in 0.43.0 (2025). |
| **Parca agent** | 5.4+ | perf_event + kprobe | Go | <1% overhead at 19 Hz sampling. |
| **bcc** | 4.1+ | kprobe | Python/Lua | Slow startup (LLVM on target), obsoleted for new code. |
| **bpftrace** | 4.9+ | kprobe/tracepoint | DSL | One-liners, ad-hoc probing. |
| **Aya** | 4.15+ | any | Pure Rust | CO-RE "still maturing" — multiple 2025 bug reports of verifier rejections traced to Rust-LLVM CO-RE gaps. |
| **libbpf-rs** | 5.2+ | any | Rust wrapping libbpf | Battle-tested CO-RE. Cloudflare uses in prod. |

**Shape of the consensus:** Go projects pick `cilium/ebpf`; C++ projects pick `libbpf`; Rust projects that want CO-RE today pick **`libbpf-rs`**, and those willing to accept maturing CO-RE pick Aya for the pure-Rust toolchain.

---

## 2. Tooling recommendation: `libbpf-rs` for `trust-bpf`

### 2.1 The three candidates for our sidecar

| Criterion | `libbpf-rs` | `Aya` | `bpftrace` |
|---|---|---|---|
| Language of eBPF program | C (.bpf.c) | Rust | `bpftrace` DSL |
| Language of loader | Rust | Rust | — (CLI) |
| CO-RE support | **First-class** (via libbpf 1.x) | Maturing, LLVM-Rust experimental | N/A (runtime) |
| Old-kernel fallback | Yes — BTF sideload via pahole | Partial | Yes (kprobe events) |
| Build dependencies | libbpf headers, clang, bpftool | Rust toolchain + experimental LLVM | bpftrace binary |
| Ergonomics | Idiomatic Rust with generated skeletons | Pure Rust end-to-end | Shell-level |
| Debuggability | Mature (`bpftool prog show`) | Improving | Ad-hoc |
| Fit with existing codebase | Userspace in Python today; loader would be a new `trust-bpf` Rust crate | Same | Scripts only |
| Risk | Low — this is the path Cilium/Facebook/Cloudflare use | Medium — bleeding edge | Low for scripts |

**Choice: `libbpf-rs`.**

Reasoning:
1. **CO-RE is not optional for us.** The project targets 5.4+ (Arch rolling) but also old hardware where 5.10 LTS is the lowest reasonable floor. A single `.bpf.o` that runs on every Arch kernel from 5.10 to 6.18 is only available with mature CO-RE. Aya's CO-RE is "still maturing and relies on experimental LLVM features for Rust" (documented developer reports in 2025 of hitting verifier rejection from Rust-emitted BPF).
2. **We already have C in the kernel module.** A `.bpf.c` file matching `trust_internal.h` types is lower friction than re-declaring everything in Rust.
3. **bpftrace is a diagnostic, not an agent.** We'd still want it as a tool (see §9) but not as the runtime.
4. **Rust for the loader** is consistent with the direction this project could credibly head — it is the only modern systems-programming choice that gets the safety properties we're marketing via `trust.ko`.

**Secondary choice (if libbpf-rs is rejected):** `cilium/ebpf` (Go). Mature, used by Cilium and Tetragon. Would mean adding a Go build step.

**Do not choose:** `bcc`. Slow startup (LLVM-on-target), obsoleted by modern alternatives, no CO-RE.

### 2.2 Architecture of the proposed `trust-bpf` sidecar

```
┌────────────────────────────────────────────────────────┐
│ Userspace                                              │
│                                                        │
│   ai-control.service (Python/FastAPI, port 8420)       │
│            ▲                                           │
│            │ consumes events via Unix socket           │
│            │ /run/pe-compat/events.sock (v2 NDJSON)    │
│   ┌────────┴─────────────┐                             │
│   │ trust-bpf (Rust)     │ ← libbpf-rs                 │
│   │                      │                             │
│   │ • loads *.bpf.o      │                             │
│   │ • pins maps          │                             │
│   │ • reads ringbuf      │                             │
│   │ • normalises +       │                             │
│   │   republishes on     │                             │
│   │   /run/pe-compat/    │                             │
│   └────────┬─────────────┘                             │
└────────────┼───────────────────────────────────────────┘
             │ BPF syscalls
             ▼
┌────────────────────────────────────────────────────────┐
│ Kernel                                                 │
│                                                        │
│   BPF subsystem                                        │
│    • fentry/fexit on sys_openat, read, write, ioctl…   │
│    • LSM hooks on security_file_open, bprm_check_sec…  │
│    • ringbuf map  →  fanout to trust-bpf               │
│    • PID hashmap  →  "is this PID observed?"           │
│                                                        │
│   trust.ko (SMALLER)                                   │
│    • APE proofs                    │ unchanged —       │
│    • token economy                 │ this is the moat  │
│    • chromosome state              │                   │
│    • /dev/trust ioctl              │                   │
│    • NO MORE kprobe/netlink        │ ← deleted ~1400 LOC
│                                                        │
└────────────────────────────────────────────────────────┘
```

Every byte that leaves `trust.ko` reduces the attack surface that an exploit inside the kernel module would expose. The eBPF verifier becomes the trusted boundary for observation; `trust.ko` becomes the trusted boundary for *authority decisions*. Those are different security arguments and should live in different places.

---

## 3. What can move to eBPF

### 3.1 Concrete retargeting map

Each row is a piece of today's `trust_syscall.c` mapped to an eBPF program type.

| Current code | Current mechanism | Move to eBPF? | Proposed program type | Notes |
|---|---|---|---|---|
| `tsc_kp_openat_pre` | kprobe on `__x64_sys_openat` | **Yes** | `fentry/openat` on 5.5+, kprobe fallback on <5.5 | 10× faster via BPF trampoline (Bootlin, Oracle benchmarks). |
| `tsc_kp_read_pre` / `write_pre` | kprobe | **Yes** | fentry | Same. |
| `tsc_kp_ioctl_pre` | kprobe | **Yes** | fentry | Same. |
| `tsc_kp_socket_pre` / `connect` / `bind` | kprobe | **Yes** | fentry, plus LSM `socket_connect` for enforcement | LSM path is authoritative — deny returns -EPERM before the connect() proceeds. |
| `tsc_kp_mmap_pre` | kprobe | **Yes** | fentry, plus LSM `file_mprotect` | |
| `tsc_kp_clone_pre` | kprobe | **Yes** | `sched_process_fork` tracepoint | Tracepoints are more stable than kprobes. |
| PID bitmap (`g_tsc.pid_bitmap`) | 32 768-bit static bitmap | **Yes** | `BPF_MAP_TYPE_HASH` keyed by PID, value = `subject_id` | Hash-map gives O(1) and unbounded, beats static bitmap. |
| Per-PID ring buffer (`tsc_pid_slot.ring`) | 4096 `struct tsc_event` per PID | **Yes** | Single kernel-wide `BPF_MAP_TYPE_RINGBUF` | Much cheaper than per-PID arrays; consumer handles fan-out. |
| Per-syscall counters (`stats[512]`) | `u64[512]` per PID | **Yes** | `BPF_MAP_TYPE_PERCPU_HASH` | Native percpu accumulation; aggregate in userspace. |
| Netlink fan-out (`nlmsg_multicast`) | NETLINK_GROUP multicast | **Yes** | ringbuf + userspace fanout | Ringbuf is cheaper and doesn't need netlink machinery. |
| Category mask filter | `slot->category_mask & category` | **Yes** | In-BPF check + `bpf_ringbuf_reserve` early-exit | Identical logic, lower overhead. |
| Event sequence counter (`atomic_inc_return(&g_tsc.event_seq)`) | global atomic | **Yes** | `bpf_ktime_get_ns()` as timestamp, userspace does sequencing | Clock-sourced ordering avoids contention. |

### 3.2 New capabilities unlocked by the move

- **Syscall gates become enforcement, not just observation.** Today `trust_syscall.c` only records — it cannot stop a syscall. An **LSM-BPF hook** can return `-EPERM` from `security_file_open`, `security_socket_connect`, `security_bprm_check_security`, etc. This fills a genuine gap: today a low-trust PE binary can still call `connect()`, we log it, and the cortex reacts *after the fact*. With LSM-BPF we can deny at the gate, before the syscall completes. This is what Tetragon calls "enforcement mode" and it uses `bpf_override_return` / `bpf_send_signal`.

- **PE-process selection via cgroup.** We can put every PE-loader child in a dedicated cgroup (`/sys/fs/cgroup/pe-compat/`) and attach cgroup-scoped BPF programs. Programs only fire for that cgroup — zero cost for non-PE processes. Currently every PID hits the kprobe and we filter in-handler.

- **Periodic ticks via `bpf_timer`.** `trust_decay_timer_fn` (runs every 1 s in the kernel module) can move to a `bpf_timer` in its map-value, removing another timer from the kernel-module surface. (5.15+; fine for our targets.)

- **Structured observability to userspace via BPF arena.** On 6.9+ we can `mmap` a BPF arena for the ringbuf's overflow buffer, and the cortex can read it with zero syscall cost. This is the cleanest answer to the chromosome-segment exposure question (see §3.3).

### 3.3 Chromosome/segment state — keep in kernel, export via ringbuf

`trust_chromosome.c` + `trust_meiosis.c` hold the runtime A-segment / static B-segment state that is *part of the authority model*. That must stay in the kernel module because the authority chain signs against it. But the **snapshot** for userspace consumption (what the cortex reads to display trust posture) can be written to a BPF arena / ringbuf on each meiosis event. Current code uses the `/dev/trust` ioctl for this — `TRUST_IOC_CHROMO_QUERY` — which is a synchronous pull. A push-based ringbuf is cheaper and gives the cortex a continuous view without polling.

---

## 4. What MUST stay in `trust.ko`

Being explicit about this is as important as the move-list. These are the properties that make the trust kernel module the system's "moat" (S64 A5 audit language):

1. **Authority Proof Engine (APE).** `trust_ape.c` — self-consuming proof chain. Proofs are destroyed on read; the cryptographic primitive cannot migrate to an eBPF program because eBPF cannot perform unbounded loops and has no stable place to keep self-consuming state across process boundaries.
2. **Token economy ledger (TRC).** `trust_token.c` — fixed-point cost multiplier, balance arithmetic, regen tick. Moving this to BPF maps would invite the "inconsistent accounting across CPUs" bug that percpu maps introduce; the in-kernel spinlock is correct here.
3. **Subject lifecycle.** `trust_lifecycle.c`, `trust_meiosis.c` — mitotic/meiotic transitions, immune response. These touch signed chromosomal state; the signing key (if any) lives in the module.
4. **ISA dispatcher.** `trust_dispatch.c` — `[family][opcode]` function pointer table. This is a userspace-submitted command buffer interpreter; it must stay authoritative.
5. **`/dev/trust` ioctl surface.** The contract between libtrust and the kernel. Can't move; userspace ABI.
6. **Chromosome persistence.** State must survive process death; BPF maps die with the loader process unless pinned, and even then they're not crypto-authenticated.
7. **`subject_id` allocation.** The root of the subject namespace. If eBPF assigned subject IDs, we'd need a separate trust round-trip to validate every eBPF event, defeating the purpose.
8. **Kernel driver gating.** S65 A1's `TRUST_ACTION_LOAD_KERNEL_BINARY` and the Authenticode shape check. That is a kernel-space authority decision and cannot move. (eBPF can detect + signal the module, but the verdict stays.)

### 4.1 The rule

> **Observation moves out. Authority stays in.**

An eBPF program is allowed to *say what happened* but not to *decide what is allowed*. Decisions call back into `trust.ko` via a pinned BPF program of type `BPF_PROG_TYPE_LSM` which itself calls `bpf_kfunc` exported from the trust module. That preserves the authority chain: userspace proposes, eBPF observes, `trust.ko` decides.

---

## 5. Old-hardware analysis

### 5.1 What "old hardware" means for us

CLAUDE.md's "old-hardware" constraint is typically interpreted as "Arch Linux installed on 2012–2020 Intel / AMD desktops." Arch is a rolling release (`wiki.archlinux.org/title/Kernel`), so these machines are **already running current kernels**. The relevant question is not "what kernel does the hardware support" but "what kernel does the user actually have".

Let us split:

| Scenario | Kernel range | Representative install |
|---|---|---|
| **Arch rolling**, current | 6.1 → 6.18 | `linux 6.18.x` (default) |
| **Arch LTS**, current | 6.12 → 6.18 LTS | `linux-lts 6.18.22-1` ships on the 2026-04 ISO |
| **Arch user pinned to LTS** (conservative admin) | 6.6 LTS | Dropped from repos ~2025 |
| **Other distros running our packages** | 5.10 → 6.x | Debian 12 (`linux-image-6.1`), RHEL 9 (`5.14`), Ubuntu 22.04 (`5.15`) |
| **Truly ancient hardware** | 4.19 or 5.4 | We would not support. |

**Concrete floor for CO-RE:** 5.4 LTS (Ubuntu 20.04). Above that, CO-RE works out of the box. Below 5.4, we'd either need to ship BTF sidecar (pahole-generated) or gracefully fall back to the legacy netlink/kprobe path that `trust_syscall.c` already implements.

### 5.2 Proposed graceful fallback

```
┌─────────────────────────────────────────────────┐
│ trust-bpf startup                               │
│                                                 │
│   if kernel ≥ 5.7 && BTF present:               │
│       load LSM + fentry + ringbuf *.bpf.o       │
│       disable trust.ko's kprobe path            │
│                                                 │
│   elif kernel ≥ 5.4 && BTF present:             │
│       load fentry + ringbuf *.bpf.o             │
│       (no LSM — observation only)               │
│       disable trust.ko's kprobe path            │
│                                                 │
│   elif kernel ≥ 4.15:                           │
│       keep trust.ko's netlink/kprobe path       │
│       log that we're in fallback mode           │
│                                                 │
│   else:                                         │
│       refuse to start; supported kernels ≥ 4.15 │
└─────────────────────────────────────────────────┘
```

This means the eBPF path is *opt-in by virtue of having the kernel to support it* — we never regress a working install. The `trust.ko` kprobe code stays in tree as a fallback for at least one more release cycle; we can delete it when the 5.4 floor is uncontroversial (realistically, by the 2027 ISO).

### 5.3 BTF sideload for edge cases

For kernels where `CONFIG_DEBUG_INFO_BTF=n` (some vendored kernels, some ARM SoCs), libbpf-rs can consume a sideloaded BTF blob generated with `pahole -J vmlinux`. We'd ship a `mkbtf` tool with the package; it runs once at install time on the user's vmlinux, produces `/var/lib/trust-bpf/vmlinux.btf`, and the loader sideloads it. This is the Void Linux workaround (`github.com/void-linux/void-packages/issues/53258`).

---

## 6. New hardware opportunity: BPF arena, sched_ext

### 6.1 BPF arena (6.9+)

The cortex's event-bus consumer today parses NDJSON over a Unix socket (v2 schema, `docs/architecture.md` §4, `pe-loader/include/eventbus/pe_event.h`). That's ~1 MB/s of JSON at worst. An alternative path on 6.9+:

- Kernel eBPF writes packed `struct tsc_event` into a 256 MB BPF arena.
- Userspace `mmap`s the arena at a known base.
- Cortex reads directly — zero syscalls for event consumption.

The existing NDJSON path stays for cross-host / cross-layer consumers. Arena is a fast-path for same-host cortex. This is "aspirational" in the CLAUDE prompt's sense but it is concretely implementable on the 2026 Arch default kernel.

### 6.2 sched_ext (6.12+)

`sched_ext` lets us ship a **trust-aware CPU scheduler** without patching the kernel:

- A low-trust PE process gets less CPU share (or gets the "batch" SCX class).
- A high-trust process gets priority in the runqueue.
- The scheduler reads `subject_id → trust_score` from a pinned BPF map that `trust.ko` writes on TRC repartition.

This is exactly the use case Meta runs in production (`scx_rusty`, `scx_layered`). Value for us:
- **Operationally differentiating.** Nobody else has trust-weighted scheduling out of the box.
- **Low risk.** If the eBPF scheduler faults, 6.19 adds automatic fallback to CFS; the system cannot deadlock.
- **Measurable.** Meta's published figures show ~15% tail-latency improvement on mixed workloads.

Treat this as an S75+ aspiration — not critical path, but a strong Phase 3 feature.

### 6.3 Signed eBPF

Boscaccy / Wang two-phase signing at bpfconf 2025 — not yet upstream as of 2026-04, but the path is clear:
1. Compile-time: sign the original `.bpf.o` against a project key.
2. Load-time: after libbpf relocation, re-sign the modified program.
3. Kernel verifies both signatures.

When this lands (expected 2026 second half), we adopt it immediately. Gains: `trust.ko` can verify that only project-signed eBPF programs attach to its hooks. That closes the "attacker with CAP_BPF loads a malicious eBPF program that impersonates trust-bpf" surface.

---

## 7. Implementation cost estimate

### 7.1 Session-by-session plan

| Session | Work | LOC delta | Risk |
|---|---|---|---|
| **S72** | Stand up `trust-bpf/` crate skeleton (libbpf-rs). Single fentry on `sys_openat`, ringbuf back to userspace, bridge ringbuf events to `/run/pe-compat/events.sock` v2 NDJSON. Verify parity on pkg-17 ISO. | +800 Rust, +200 C (.bpf.c), +0 kernel | Low. Purely additive. |
| **S73** | Extend to all 9 syscalls currently in `trust_syscall.c`. Add PID hashmap (replacing bitmap). Add category mask. | +1200 Rust/C | Low. |
| **S74** | Add LSM-BPF hooks for enforcement — `security_file_open`, `security_socket_connect`, `security_bprm_check_security`. Wire to `trust.ko` decision via BPF kfunc. Gate behind `TRUST_ENFORCEMENT=on` env. | +600 Rust/C, +80 kernel (kfunc export) | Medium. First enforcement surface. |
| **S75** | Behind a feature flag, disable `trust_syscall.c`'s kprobe path when `trust-bpf` is active and healthy. Retain code for fallback. | −0 (dead code, gated) | Medium. |
| **S76** | BPF arena event path for cortex (6.9+ only). NDJSON path retained. | +400 Rust, +100 C | Medium. Kernel-version gate. |
| **S77** | Two-phase signing integration (if upstream by then). | +200 Rust | Low. |
| **S78+** | `sched_ext`-based trust-weighted scheduler. Separate crate, separate package. | +1500 Rust/C (new) | Higher. Production-scheduler risk. |

**Total to reach "eBPF is the primary observation path, `trust.ko` kprobes are dead code": 4 sessions, ~3000 LOC.**

### 7.2 What we delete

Once the eBPF path is the primary:

- `trust/kernel/trust_syscall.c` (1400 LOC) — becomes fallback, eventually deletable.
- `trust/kernel/trust_syscall.h` — same.
- Netlink group `TSC_NETLINK_GROUP` — dead.
- 9 kprobe struct registrations + kretprobe mirrors — dead.
- Per-PID bitmap allocation — dead.
- `/dev/trust` ioctls `TRUST_IOC_TSC_*` (120-123) — fallback only.

**Net: ~1800 LOC removed from the kernel module.** That's a substantial attack-surface reduction for roughly the same LOC added to userspace Rust, which is the trade we want.

### 7.3 What we keep in `trust.ko` (explicit)

From §4 — APE, TRC, lifecycle, dispatch, ioctl, chromosome, subject_id alloc, kernel driver gating. This is 17 `.c` files of the 22 (down from today's 22). `trust.ko` shrinks to purpose: **the authority root**.

---

## 8. Risks

### 8.1 eBPF-side risks

- **Verifier changes.** BPF verifier is the most active kernel subsystem. A program that passes on 6.1 may be rejected on 6.2 (rare but documented). Mitigation: CI the eBPF object against a kernel matrix; keep programs simple; subscribe to `linux-bpf@` for regression notices.
- **LSM hook stability.** LSM-BPF is technically ABI-stable at the hook level but the *behavior* of each hook can shift as the security subsystem evolves. Mitigation: pick widely-used hooks (same ones Tetragon attaches to); avoid obscure ones.
- **Upstream drift.** eBPF helpers come and go (rarely). Mitigation: CO-RE + feature detection at load time.
- **Verifier CVEs as attack vector.** As §1.2 notes — we're loading as root, so the exposure is from inside the trust domain. Less critical than unpriv-escape but still warrants program narrowness.
- **Operational complexity.** An extra service (`trust-bpf.service`). Mitigation: single binary, systemd unit, health check via `/run/trust-bpf/health` socket consumed by `ai-control`.

### 8.2 Trust-side risks

- **Authority chain gets split across boundaries.** If we're not careful, someone will write code that trusts an eBPF event without verifying via `trust.ko` — bypassing the moat. Mitigation: document the "observation ≠ decision" rule in `docs/architecture.md`; enforce in code review.
- **Race: eBPF event arrives before `trust.ko` has allocated subject_id.** Today `trust_syscall.c` gates on `tsc_is_pid_traced()`. In the new design, the BPF program filters on cgroup membership, which is set by the PE loader *before* `execve`. So the race goes the other way — BPF sees events before `trust.ko` sees the subject. Mitigation: userspace `trust-bpf` buffers events for up to 100 ms waiting for subject binding; otherwise emits with `subject_id = null` (schema v2 already allows).
- **cgroup v1 machines.** Some old systems still run cgroup v1 hybrid mode. Mitigation: detect at startup; fall back to whole-system attach + PID-map filter.

### 8.3 Political risks

- **"eBPF is just netlink with extra steps."** A future maintainer may not see the value. Mitigation: memoize the argument — attack surface reduction + enforcement capability + no module ABI churn across kernel versions.
- **"We're competing with Tetragon."** We're not — Tetragon is Kubernetes-aware generic policy. We're a single-host, trust-kernel-bound enforcer. Different scope.

---

## 9. Recommendation for next session

**S72 action:** Create `trust-bpf/` crate with the minimum viable loop:
1. `trust-bpf/bpf/syscall_openat.bpf.c` — single fentry on `sys_openat`, emits `(pid, subject_id_lookup, ktime, dfd, filename_hash)` into a ringbuf.
2. `trust-bpf/src/main.rs` — libbpf-rs loader, reads ringbuf, emits v2 NDJSON to `/run/pe-compat/events.sock`.
3. `trust-bpf.service` systemd unit, `After=ai-control.service`, `User=root`, `AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN`.
4. `ai-control/daemon/trust_translate.py` extension: when an event arrives via the new path, tag `source=trust-bpf` in schema v2.
5. Parity test: boot pkg-17 ISO with `trust-bpf` running **alongside** the existing `trust_syscall.c` kprobe path. Confirm both report identical events for the same PE workload.

If that parity holds, S73 extends to the remaining 8 syscalls and we begin the soft-sunset of the kprobe path.

**Do NOT:**
- Delete any of `trust_syscall.c` in S72. The eBPF path must prove itself for at least one session before it becomes load-bearing.
- Wire enforcement (LSM return -EPERM) in S72. Observation only. Enforcement lands in S74 behind a flag.
- Attempt Aya until CO-RE stabilises upstream in Rust-LLVM. Watch bi-annually; revisit when the "experimental LLVM features" language disappears from Aya's README.

**One-line recommendation:**
> Start a `trust-bpf` sidecar on libbpf-rs in S72, observe in parallel with the kprobe path, move enforcement into LSM-BPF in S74 behind a flag, delete ~1800 LOC from `trust.ko` by S76.

---

## 10. References

1. eunomia — "eBPF Ecosystem Progress in 2024–2025: A Technical Deep Dive" (2025-02-12). https://eunomia.dev/blog/2025/02/12/ebpf-ecosystem-progress-in-20242025-a-technical-deep-dive/
2. `iovisor/bcc` — "BPF Features by Linux Kernel Version" (ongoing). https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
3. eBPF Docs — "Program Type BPF_PROG_TYPE_LSM" (ongoing). https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/
4. Tetragon — "Tetragon: Extending eBPF and Cilium to runtime security", InfoWorld (2025-04 window cited by Isovalent). https://www.infoworld.com/article/3810607/tetragon-extending-ebpf-and-cilium-to-runtime-security.html
5. Cilium blog — "Securing the Modern Process with Tetragon: Runtime Security for the Cloud-Native Kernel" (2025-11-04). https://cilium.io/blog/2025/11/4/process-tetragon/
6. Falco — "Getting started with modern BPF probe in Falco" (2023, still current in 2026). https://falco.org/blog/falco-modern-bpf/
7. Phoronix — "Linux 6.12 Preps For Release With Real-Time, Sched_Ext, Stable Xe2 & Raspberry Pi 5" (2024-10-22). https://www.phoronix.com/news/Linux-6.12-Feature-Reminder
8. eunomia tutorial — "BPF Arena for Zero-Copy Shared Memory". https://eunomia.dev/tutorials/features/bpf_arena/
9. Nakryiko — "BPF CO-RE reference guide" (canonical). https://nakryiko.com/posts/bpf-core-reference-guide/
10. Bootlin — "Bouncing on trampolines to run eBPF programs" (kprobe vs fentry benchmark). https://bootlin.com/blog/bouncing-on-trampolines-to-run-ebpf-programs/
11. iximiuz Labs — "eBPF Tracepoints, Kprobes, or Fprobes: Which One Should You Choose?" (2024+). https://labs.iximiuz.com/tutorials/ebpf-tracing-46a570d1
12. Aya — GitHub README (2026-04 snapshot shows v0.13.x). https://github.com/aya-rs/aya
13. Google security research — "Linux Kernel: Vulnerability in the eBPF verifier register limit tracking". https://github.com/google/security-research/security/advisories/GHSA-hfqc-63c7-rj9f
14. SecurityOnline — "CVE-2024-56614 & CVE-2024-56615: PoC Exploits Released for Severe eBPF Vulnerabilities in Linux Kernel". https://securityonline.info/cve-2024-56614-cve-2024-56615-poc-exploits-released-for-severe-ebpf-vulnerabilities-in-linux-kernel/
15. 9to5Linux — "Arch Linux Kicks Off 2026 with New ISO Powered by Linux Kernel 6.18 LTS". https://9to5linux.com/arch-linux-kicks-off-2026-with-new-iso-powered-by-linux-kernel-6-18-lts
16. Boscaccy / Wang — "Two-Phase eBPF Program Signing" (bpfconf 2025 material). https://bpfconf.ebpf.io/bpfconf2025/bpfconf2025_material/Two-Phase%20eBPF%20Program%20Signing.pdf
17. Kaiming Huang et al — "SoK: Challenges and Paths Toward Memory Safety for eBPF" (IEEE S&P / Oakland 2025). http://www.nebelwelt.net/files/25Oakland.pdf

---

## Appendix A: Verified-vs-unverified claims

| Claim | Source | Confidence |
|---|---|---|
| BPF arena merged in 6.9 | Isovalent + Phoronix; internal consistency across 3 sources | Verified |
| `sched_ext` merged in 6.12 | Phoronix + kernel.org scheduler docs | Verified |
| Arch ISO 2026-01 ships 6.18 LTS | 9to5linux, archlinux.org/releng/releases/ | Verified |
| Tetragon 1.68% overhead on kernel build | Isovalent blog (Tetragon 1.0 release) | Verified |
| Falco modern-bpf requires ≥5.8 in practice (officially no minimum but feature-bound) | Falco docs | Verified |
| Aya's CO-RE "still maturing, LLVM-Rust experimental" in 2025 | Multiple dev blog posts including Riyao Lin (Medium) and the galiglobal 2025 Aya guide | Verified (multiple corroborating sources) |
| Two-phase signing not yet upstream as of 2026-04 | bpfconf 2025 materials are proposals, not merged | Verified |
| kprobe vs fentry ~10× speedup | Bootlin blog + Oracle blog | Verified with caveat that "10×" is workload-dependent |
| Meta ships `sched_ext` in production at scale | Multiple public talks + Phoronix coverage | Verified |
| Arch rolling-release users on 6.1+ by 2026 | ArchWiki kernel page + release history | Verified |
| **Unverified:** exact percentage of "old-hardware Arch installs" still on <5.4 | No reliable telemetry; estimate based on Arch's rolling model ≈ 0%, but unmeasured | **UNVERIFIED** — flagged |
| **Unverified:** specific LOC reduction (~1800) | Based on `trust_syscall.c` + `trust_syscall.h` size; rough estimate not line-counted post-retirement | **UNVERIFIED** — flagged |
| **Unverified:** kernel 6.19 "15% latency boost" figure | Single source (webpronews.com), not cross-checked | **UNVERIFIED** — flagged |

End of report.
