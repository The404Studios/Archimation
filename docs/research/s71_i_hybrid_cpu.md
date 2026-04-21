# S71-I: Hybrid-CPU-Aware Scheduling for ARCHIMATION

**Research agent:** I (of 12).
**Date:** 2026-04-20.
**Scope:** How Linux schedules on hybrid / heterogeneous CPUs (Intel P+E, AMD chiplet+X3D, ARM big.LITTLE / DynamIQ, Apple M-series) in 2024-2026, and how ARCHIMATION should exploit the kernel surface *without* inventing a scheduler we can't maintain.
**Verdict:** **Stand on the mainline stack (EEVDF + amd-pstate/intel-pstate + EAS + cache-aware load-balancing) on every tier. On NEW hardware add a single sched_ext BPF scheduler (`scx_lavd` first; a custom `scx_archimation` layered variant later) attached to `pe-compat.slice`. On OLD hardware attach nothing. Raise latency sensitivity for the AI daemon via `latency_nice`; use `AllowedCPUs` for IRQ/game isolation (already done). No CPU affinity for the cortex — it is an E-core consumer by design.**

---

## 0. Why this research matters for ARCHIMATION

ARCHIMATION runs four very different workloads on a single machine:

| Workload | Latency class | Runtime shape | Right CPU tier |
|---|---|---|---|
| **Foreground PE game** | Hard (≤1 frame ≈ 16.6 ms at 60 FPS, 8.3 ms at 120 FPS) | Busy loops, 8-16 worker threads, spiky | **Fastest P-core cluster with biggest L3 / 3D V-Cache CCD** |
| **AI control daemon** (`ai-control.service`, port 8420) | Soft (<100 ms for websocket wake-ups) | Bursty, small RSS | One P-core is enough; doesn't need a cluster |
| **AI cortex** (decision loop, Markov chains, optional LLM inference) | Bulk (seconds) | Periodic batch | **E-core tier** — this is the textbook E-core use case |
| **Trust kernel gating** | Hard but rare (`trust.ko` ISA per-syscall check) | Runnable ~microseconds | Wherever the gated process already is |

A single static policy cannot serve all four. Historically ARCHIMATION had only `CPUWeight` + `AllowedCPUs` + NUMA-pin helpers (see `slice-apply.sh:231-275` and `game.slice:40-100`) — perfectly good but tier-blind. Hybrid-CPU hardware has shifted the frontier: the cheapest lever now is to hand the kernel the right *hints* and let mainline do its job, not to write our own scheduler.

The mainline kernel has absorbed more scheduler improvements in the last 30 months than the prior decade. This report is the inventory of what ships, what we can use today, and the one specific experiment worth S72.

---

## 1. Hybrid-CPU landscape 2026

### 1.1 Intel: P+E (+LP-E)

| Gen | Year | Topology | Thread Director? | Linux floor |
|---|---|---|---|---|
| **Alder Lake** (12th) | 2021 | 8P (SMT) + 8E | Gen-1 HFI | 5.16 (basic) / 5.18 (HFI/ITD landed) |
| **Raptor Lake** (13-14th) | 2022-23 | up to 8P + 16E | Gen-2 HFI | 6.0+ |
| **Meteor Lake** (Core Ultra S1) | 2023 | 6P + 8E + **2 LP-E** (SoC tile) | Gen-3 | 6.7 (capacity scaling landed) |
| **Arrow Lake** (Core Ultra 200S) | 2024 | 8P + 16E, **no SMT** | Gen-3 | 6.10-6.12 (cluster sched + capacity scale) |
| **Lunar Lake** (Core Ultra 200V) | 2024 | 4P + 4LP-E (no SMT) | Gen-3 | 6.10-6.11 (hybrid capacity + intel-pstate) |

Intel Thread Director communicates a 0–255 performance and a 0–255 energy-efficiency score per running thread via the **Hardware Feedback Interface (HFI)**. The Linux kernel began consuming HFI in 5.18 (core concept) and gained first real use for load-balancing in 6.0. 6.6 re-introduced cluster scheduling for hybrid CPUs after the 2022 retreat (Atom-cluster vs P-core-SMT bug — [LWN 909611](https://lwn.net/Articles/909611/)). 6.7 added cluster-aware load-balancing; 6.10-6.12 added hybrid capacity scaling for chips without SMT (Arrow/Lunar Lake) so the scheduler doesn't pretend all cores are peers of the fastest P-core.

The rough state of the art:
- **2022-early 2024:** Linux noticeably trails Windows on Alder/Raptor Lake for gaming; Phoronix tests show 3-8% variability vs Windows, the gap is the scheduler.
- **2025+:** The gap has closed and in some cases inverted. Tom's Hardware ([Core Ultra 9 285K benchmark](https://www.tomshardware.com/pc-components/cpus/core-ultra-9-285k-is-faster-in-linux-than-in-windows-flagship-arrow-lake-chip-is-6-to-8-percent-faster-on-average-in-linux)) measured Arrow Lake 6–8% *faster* on Linux than Windows 11 on average workloads — largely attributed to cluster-aware scheduling + newer `intel-pstate` driver + distro-level defaults.

### 1.2 AMD: chiplets + 3D V-Cache

AMD's scheduling problem is different: topology, not heterogeneity.

- **Zen 2+ ("preferred core")**: ACPI CPPC tells the OS which physical core binned highest. `amd-pstate` consumed this in kernel **6.9** (`amd_prefcore`, 2024 — [Phoronix](https://www.phoronix.com/news/AMD-P-State-Preferred-Core-69)). Under load the scheduler now pins latency-critical tasks to the fastest-binned core first.
- **X3D (Ryzen 5800X3D, 7800X3D, 7950X3D, 9800X3D, 9950X3D)**: One CCD has 64-96 MB of stacked 3D V-Cache; the other CCD (on dual-CCD chips) does not. A game that dances between CCDs pays the cross-CCD-cache miss penalty on every migration (the infamous "1-second lag spike"). Windows 11 had to ship Xbox Game Bar to tell its scheduler which CCD to pin to; Linux takes a different road.
- **Cache-aware scheduling / load balancing** (Chen Yu + Tim Chen, posted v4 Sep 2025 — [Phoronix Cache-Aware-Balancing-v4](https://www.phoronix.com/news/Cache-Aware-Balancing-v4)): records per-LLC utilization in `fair.c` and prefers to keep a thread group inside a single LLC (i.e., a single CCD on Zen). The v4 Ryzen 9950X3D benchmark shows 5-12% wins on cache-sensitive workloads (game/compression) with the knob on. Merge target kernel 6.18 as of this writing.
- **Strix Halo** (Ryzen AI Max 395+, 2025): 16-core Zen 5, single CCD with RDNA 3.5 40-CU iGPU on the same package. Scheduler still matters because 8+8 cores split across clusters, but cache is unified — cleaner story than desktop X3D.

### 1.3 ARM: DynamIQ, EAS

ARM's "Energy Aware Scheduling" has been mainline for years ([kernel.org Energy Aware Scheduling](https://www.kernel.org/doc/html/latest/scheduler/sched-energy.html)). EAS uses a per-platform **Energy Model** (from device tree or SCMI firmware) to pick the CPU tier that executes a task at the lowest joules while meeting compute demand. "Capacity" is normalized 0-1024 per CPU so the scheduler sees P-cores as ~1024-capacity units and E-cores as ~500-capacity (or whatever the DTB reports).

- **DynamIQ** (Cortex-A78 + A55 combos, modern phones): EAS has handled this for years.
- **Snapdragon X Elite** (Qualcomm Oryon, 2024 laptops): 12 performance cores, *no* E-tier — a "flat" cluster. Scheduler just uses cluster awareness; EAS not really doing asymmetric work. Linux support mainlined on launch day (Qualcomm Oryon push to 6.8-6.11, [Qualcomm Linaro blog](https://www.qualcomm.com/developer/blog/2024/05/upstreaming-linux-kernel-support-for-the-snapdragon-x-elite)).
- **Apple M-series**: 4P + 4E (M1/M2), 8P + 4E (M2 Max), 12P + 4E (M4 Max). Asahi Linux's chadmed (James Calligeros) implemented EAS + utilization clamping in 2024 ([Phoronix Asahi Jan 2024](https://www.phoronix.com/news/Asahi-Linux-January-2024)): M2 MacBook Air battery life on Asahi went from ~6 h desktop-idle to 8-10 h playing YouTube and 12-15 h desktop use **because the kernel finally learned to park background work on E-cores**. Strong proof that EAS-on-mainline *is* the right approach and does not need reinventing.

### 1.4 Old hardware

The overwhelming majority of the hardware ARCHIMATION supports (Sandy/Ivy Bridge 2-core laptops, Core 2 Quad desktops, single-core 2005 P4s) is **homogeneous**. No Thread Director, no cluster scheduling value, no preferred core, no EAS (no asymmetric capacity to model).

Mainline EEVDF in 6.6+ is the right scheduler for every OLD machine we'll ever see. No tuning required, no hybrid logic firing. `hw-detect.sh` already sets `ondemand` governor and `bfq` I/O scheduler on OLD; we add nothing CPU-scheduler-wise.

---

## 2. Linux scheduler evolution: CFS → EEVDF → sched_ext

### 2.1 CFS (2007-2023)

`kernel/sched/fair.c`. Ingo Molnar's Completely Fair Scheduler tracked per-task **vruntime** — accumulated CPU time scaled by nice value — and ran the task with the smallest vruntime. Good at fairness, weak at latency: to give interactive tasks snap, CFS accreted heuristics (`wakeup preemption`, `min_granularity_ns`, `sched_latency_ns`, `sched_wakeup_granularity_ns`) and cgroup bandwidth controllers bolted around the edges. By 2023 the `fair.c` file had 12 kLOC of "icky heuristics" (Peter Zijlstra's phrasing on LKML).

### 2.2 EEVDF (6.6 merged, 6.12 completed)

Stoica & Abdel-Wahab 1995's **Earliest Eligible Virtual Deadline First** algorithm was merged by Peter Zijlstra for Linux 6.6 ([Phoronix Linux-6.6-EEVDF-Merged](https://www.phoronix.com/news/Linux-6.6-EEVDF-Merged), [LWN 925371](https://lwn.net/Articles/925371/)). The core change:

- Each task has a **lag** (entitled CPU minus consumed CPU). Positive lag → eligible to run.
- Each eligible task has a **virtual deadline** = eligible-time + time-slice.
- Scheduler always picks the earliest deadline among eligible tasks.
- **Time-slice is a per-task parameter** (`sched_runtime` in `sched_attr`, range 100 µs – 100 ms), exposed via `sched_setattr(2)` or `latency_nice` [-20, 19].
- A task that wants responsiveness asks for a *shorter* time-slice → earlier virtual deadline → preempts running tasks sooner.

**Why this matters for us:** the `ai-control` daemon wants low wake-up latency. Today we set `Nice=-5` in the drop-in (`profile/airootfs/usr/lib/systemd/system/ai-control.service.d/slice.conf:32`). With 6.6+, we should also set a **negative `latency_nice`** — the same mechanism but specifically about scheduling deadlines, not CPU share. (Systemd 257+ exposes this as `LatencyNice=-10`; on older systemd we can keep `Nice=-5` and set `latency_nice` via a pre-exec `schedtool`.)

EEVDF completion landed in 6.12 ([Phoronix Linux-Completing-EEVDF](https://www.phoronix.com/news/Linux-Completing-EEVDF)) — the last of the CFS-bandwidth corner cases got ported. 6.12 is also the sched_ext merge. Kernel-newbies summary: "Scheduler now expandable and EEVDF conversion complete" ([heise](https://www.heise.de/en/news/Linux-6-12-Scheduler-now-expandable-and-EEVDF-conversion-complete-9949941.html)).

Benchmarks: [jamesyoung-15/Kernel-Benchmark-CFS-EEVDF](https://github.com/jamesyoung-15/Kernel-Benchmark-CFS-EEVDF) and Linux Magazine's "A Fair Slice" both report mixed throughput (EEVDF -1% to +2% vs CFS on kernel-build, hackbench, stress-ng) but consistent **tail-latency wins**: p99 wake-up time down 15-30% on `sched-pipe`, jitter down >50% on interactive scenarios. This matches our needs (games notice jitter, not mean throughput).

### 2.3 sched_ext / SCX (6.12 merged, production-grade)

Tejun Heo & David Vernet's `sched_ext` was merged for **Linux 6.12** (Nov 2024, [Phoronix Linux-6.12-Lands-sched-ext](https://www.phoronix.com/news/Linux-6.12-Lands-sched-ext), [LKML cover](https://lkml.org/lkml/2024/5/1/564)) after an initial 6.11 miss. It gives you:

- A new scheduling class (`SCHED_EXT`) that sits *alongside* `SCHED_NORMAL` (EEVDF) and can steal tasks from it.
- BPF programs implementing `struct sched_ext_ops` (see [kernel docs](https://docs.kernel.org/scheduler/sched-ext.html)) — `enqueue`, `dispatch`, `select_cpu`, etc. — loaded at runtime.
- **Automatic fallback**: if a BPF scheduler faults, misses a deadline, or is unloaded, the kernel reverts all its tasks to EEVDF. SysRq-S force-detaches too. (6.19 added even cleaner fault recovery.)
- Dispatch queues (DSQs): one global FIFO + one per-CPU FIFO, plus arbitrary user-defined DSQs, giving the BPF program a work-stealing vocabulary out of the box.
- **cgroup v2 integration** (v7.1 cycle, 2026): sub-scheduler support means different cgroups can have different scheduling behaviors ([LKML sched_ext/for-7.1](https://lkml.org/lkml/2026/2/24/2153)).

Production status: **Meta is mass-deploying SCX_LAVD across messaging and caching tiers** ([Phoronix Meta-SCX-LAVD-Steam-Deck-Server](https://www.phoronix.com/news/Meta-SCX-LAVD-Steam-Deck-Server), [Tom's Hardware Meta data center](https://www.tomshardware.com/software/linux/facebook-deploys-the-steam-decks-linux-scheduler-across-its-data-centers-valves-low-latency-scheduler-perfect-for-managing-metas-workloads-at-massive-data-centers)); Google is committed. Fedora enables it in the default kernel (CONFIG_SCHED_CLASS_EXT=y). CachyOS ships `scx_loader` + per-profile config. This is no longer experimental.

---

## 3. sched_ext + eBPF schedulers for specialized workloads

The SCX ecosystem in `github.com/sched-ext/scx`:

| Scheduler | Target workload | Language | Status |
|---|---|---|---|
| **scx_simple** | Toy / demo | C | Reference only. |
| **scx_rusty** | General-purpose, LLC-aware | Rust | Partitions CPUs into "scheduling domains" (one per LLC) to leverage data locality. Fine baseline. |
| **scx_lavd** | **Gaming / interactive** (Steam Deck) | Rust + BPF | Igalia for Valve. Latency criticality (from wake/wait frequency and runtime) → virtual deadline. **5.2% average FPS uplift on Steam Deck Baldur's Gate 3** ([Igalia LPC slides](https://lpc.events/event/18/contributions/1713/attachments/1425/3058/scx_lavd-lpc-mc-24.pdf)). Best-validated gaming scheduler in existence. |
| **scx_bpfland** | CachyOS default, general desktop/gaming | Rust + BPF | Cache-layout-aware — keeps cooperating threads on cores sharing L2/L3. [CachyOS wiki](https://wiki.cachyos.org/configuration/sched-ext/). |
| **scx_layered** | **Multi-tenancy** — per-layer policy (cgroup-driven) | Rust + BPF | Layer = cgroup match + policy (time-slice, CPU reservation). [Meta production](https://github.com/sched-ext/scx/blob/case-studies/case-studies/scx_layered.md). **Exactly the shape we need for PE-game + AI-daemon + cortex.** |
| **scx_flatcg** | Flattened cgroup hierarchy | C | 3-10% wins on nested cgroup trees by compounding weights into a single flat layer. [sched_ext.com examples](https://sched-ext.com/docs/scheds/c). |
| **scx_rustland** | Userspace scheduler hoist | Rust (userspace) | Demo: Terraria FPS stays up during `make -j` (impressive but not production). |

The opportunity for us is real. Every SCX scheduler has a **declarative config file** that names cgroups / slices as its inputs. We already segment into `pe-compat.slice`, `game.slice`, `ai-daemon.slice`, `trust.slice`, `observer.slice` — this matches the `scx_layered` input surface one-for-one. No rewrite of our slice topology needed.

---

## 4. Priority policy for ARCHIMATION

The policy below restates the slice topology as CPU-tier placement rules. Implementation is always "describe cgroups / slices, let mainline or SCX decide the physical cores."

| Slice / process | Target tier | Weight | Policy |
|---|---|---|---|
| `trust.slice` (kernel ISA gate) | Follows gated PID — **no affinity pin** | CPUWeight=1000 | If the gated syscall came from a game on a P-core, the gate runs on that P-core. Trust has to be co-located to be cheap. |
| `pe-compat.slice/game.slice` (foreground PE game) | **P-cluster** (Intel P-cores; AMD first-CCD on X3D; P-tier on ARM; P-cores on M-series) | 900 / 10000 | `AllowedCPUs` already pinning away from `observer` (see `slice-apply.sh:182-209`). Add SCX layer with shorter time-slice for latency. |
| `ai-daemon.slice` (FastAPI, websocket HTTP) | Any P-core is fine; doesn't need cluster | 200 | Keep `Nice=-5`; add `LatencyNice=-10` on systemd 257+, or pre-exec `chrt --latency-nice -10`. |
| `observer.slice` (metrics, logs) | **E-cluster** (or reserved housekeeping CPUs on non-hybrid) | 10, 2-10% quota | Already pinned via `AllowedCPUs=${RESERVED_CPUS}` (OLD/MID HW tiers). On hybrid: pin to E-cores explicitly. |
| **AI cortex** (decision engine, Markov chains, optional LLM batch) | **E-cluster** explicitly | Part of `ai-daemon.slice` today | Split into a separate `ai-cortex.slice` so its `AllowedCPUs` can target E-cores even if daemon stays on P. |

**Key insight — why cortex on E-cores is non-obvious:** The cortex's job is bulk inference and decision loops (Markov chain hitting time, pattern scan, LLM if loaded). It is explicitly *not* latency-critical. Running it on an E-core at lower turbo frequency is:
- Within its latency budget (seconds, not frames).
- Within the game's power budget (P-cores stay available + cool for the game).
- Actually faster per-watt than a P-core because Gracemont/Crestmont E-cores have nearly identical throughput per Hz to the P-cores on integer workloads, just lower peak frequency.

The Asahi Linux M2 MacBook Air result ([Phoronix Asahi Jan 2024](https://www.phoronix.com/news/Asahi-Linux-January-2024)) — 6h → 8-15h battery by putting background work on E-cores — is the ground-truth proof point.

---

## 5. systemd tuning

### 5.1 What we already have (good)

From the survey of `profile/airootfs/etc/systemd/system/`:

- **5 slice units** covering the L0–L4 hierarchy (`trust.slice` 1000, `pe-compat.slice` 900, `game.slice` 10000, `ai-daemon.slice` 200, `observer.slice` 10). Matches the ARCHIMATION 5-layer architecture one-for-one.
- `AllowedCPUs` generated per HW tier by `slice-apply.sh` with NUMA detection — already carves reserved CPUs for observer on OLD/MID/NEW classes.
- `Nice=-5`, `IOSchedulingClass=best-effort`, `OOMScoreAdjust=-100` drop-in for the daemon.
- Governor and I/O scheduler set per HW tier in `hw-detect.sh` (ondemand+bfq for OLD, schedutil+none for NEW NVMe).

This is already well past the typical Arch / Fedora / Ubuntu default. The policy shape is right.

### 5.2 What to add

**Per-slice** (add to existing `.slice` files or drop-ins):

```ini
# trust.slice (follows gated PID, but explicit cap)
[Slice]
# EEVDF latency boost: trust wakes briefly to bless a syscall
# then sleeps — exactly the EEVDF sweet spot.
# Needs systemd 257+; on older systemd emit via pre-exec schedtool.
# LatencyNice=-15    # enable when systemd landed

# ai-daemon.slice
[Slice]
# No change needed; existing CPUWeight=200 + Nice=-5 drop-in are correct.

# ai-cortex.slice  (NEW — split out from ai-daemon.slice)
[Slice]
CPUWeight=50            # less than daemon (batch, not latency)
AllowedCPUs=            # written by slice-apply.sh based on hybrid detection
# On NEW hybrid HW: AllowedCPUs=<E-core-list>
# On NEW non-hybrid : AllowedCPUs=<RESERVED_CPUS + 1..2>
# On OLD / MID      : no override (use default)

# pe-compat.slice / game.slice
[Slice]
# Game slice already has CPUWeight=10000 and MemorySwapMax=0 — both correct.
# Opportunity: if kernel ≥ 6.12 + scx_loader service active, attach
# scx_lavd just to pe-compat.slice via scx_layered config.
```

**Hybrid-detection extension to `hw-detect.sh`:**

Needs three new fields written to `/run/ai-arch-hw-profile`:

- `CPU_HYBRID` — 0 or 1 — read from `/sys/devices/cpu_core/cpus` + `/sys/devices/cpu_atom/cpus` on Intel, or from CPU model/family on AMD/ARM.
- `P_CORE_CPUS` — cpulist of performance cores (Intel: `/sys/devices/cpu_core/cpus`; Apple: detect via `/proc/cpuinfo` clusters; AMD: via `amd_prefcore` rankings).
- `E_CORE_CPUS` — cpulist of efficiency cores.

Then `slice-apply.sh` writes a new drop-in `/run/systemd/system/ai-cortex.slice.d/20-hybrid.conf` with `AllowedCPUs=${E_CORE_CPUS}` on hybrid hosts and nothing on homogeneous.

**Boot-time cpufreq hygiene** (already partial):

- `amd-pstate=active` + `amd_prefcore=enable` on kernel cmdline when AMD CPU + kernel ≥ 6.9. We can add this to `grub.cfg` generator.
- `intel_pstate=passive` has been the Arch default since 6.3 on Alder Lake+; keep it. Set `energy_performance_preference=balance_performance` (default) for NEW, `power` for OLD if laptop on battery.

### 5.3 What to *not* do

- **Do not set `CPUAffinity=` on `ai-control.service` or `trust.ko`.** They are followers — they should run wherever the kernel sees fit. Pinning them cripples the cluster-aware balancer on hybrid CPUs.
- **Do not set `CPUSchedulingPolicy=fifo/rr` anywhere.** RT policies freeze the kernel around them and are incompatible with EEVDF's virtual-deadline reasoning unless we are writing a real-time system (we are not).
- **Do not set `SCHED_BATCH`** on the cortex unless we verify it still responds to `latency_nice`. SCHED_BATCH marks a task as throughput-only and some heuristics ignore its wake-ups.

---

## 6. Old hardware: EEVDF default is fine

Every OLD-tier ARCHIMATION install gets:

- EEVDF (kernel ≥ 6.6) — no user knobs need tuning.
- `ondemand` governor (`hw-detect.sh:141`).
- `bfq` I/O on rotational (`hw-detect.sh:168`).
- Existing slice weights.

No sched_ext: sched_ext requires `CONFIG_SCHED_CLASS_EXT=y` + BPF + BTF + 6.12 kernel. Our OLD HW often runs the LTS kernel (linux-lts 6.12.x is fine, 6.6.x is not — 6.12 is the floor) and the BPF verifier cost (small heap, slower compile on ancient CPUs) is not worth the 2-3% win on a Pentium 4. Skip it by detecting `PROFILE=OLD` in `slice-apply.sh` and never calling `scx_loader`.

**Measured expectation:** OLD tier gets the full EEVDF tail-latency win over the old CFS by default, and nothing else. That's already a silent free upgrade over Arch 2022.

---

## 7. New hardware opportunity

The opportunity side of the hybrid-CPU story:

| Hardware | Right default for ARCHIMATION |
|---|---|
| **Intel Arrow/Lunar Lake** (8P+16E or 4P+4LP-E) | EEVDF + cluster sched + HFI (all mainline). Optional `scx_lavd` on `pe-compat.slice`. |
| **AMD Strix Halo** (16-core Zen 5 + RDNA 3.5) | EEVDF + `amd_prefcore` + cache-aware sched (6.18+). No SCX needed — topology is flat enough. |
| **AMD 9950X3D** (dual CCD, one with 3D V-Cache) | Cache-aware sched (Chen Yu v4, 6.18+) keeps the game inside the X3D CCD. Optional `scx_bpfland` for explicit cache-layout hints. |
| **Apple M4 Max on Asahi** (12P+4E) | EAS + Asahi kernel patches. Nothing extra from us. |
| **Snapdragon X Elite** | Mainline kernel 6.11+, flat cluster of 12 Oryon cores. Nothing asymmetric to schedule — EEVDF alone is right. |

For NEW-tier installs, the single biggest unlock is **enabling `scx_loader` with `scx_lavd` on `pe-compat.slice`** once we detect kernel ≥ 6.12. This is a declarative change, not a code change — it installs the `scx-scheds` package, drops a config naming `pe-compat.slice`, and systemd socket-activates the scheduler when a game launches.

---

## 8. Recommendation — S72 experiment

**Ship in S72:** A **pilot of `scx_lavd` attached to `pe-compat.slice`** on NEW-tier hosts only, guarded behind a feature flag (`AI_SCX_ENABLED=true` in `/etc/ai-arch/scheduler.conf`), measured with the existing `set_smoke.py` GAME set + three Phoronix-style per-title benchmarks (OpenArena, Hitman 3 via DXVK, Cyberpunk 2077 via VKD3D-Proton).

Success criteria:
1. GAME SET stays GREEN (no regressions on existing PE corpus under the new scheduler).
2. 1% low FPS improves ≥3% on at least 2 of 3 titles (aligns with published Igalia Steam Deck numbers).
3. `scx_lavd` recoverable on fault: induce a crash via `bpftool`, verify EEVDF fallback and zero user-visible freeze.
4. OLD-tier (QEMU 1 GB P4) install has `scx_loader` inactive and is unaffected (baseline preserved).

Rollout gates:
- **Stage 1**: `scx_lavd` system-wide (default behavior on Fedora/CachyOS). Fastest to test but affects everything.
- **Stage 2**: `scx_layered` restricted to `pe-compat.slice`, everything else stays on EEVDF. This is the targeted shape — matches our slice architecture, zero risk to cortex / trust / observer. **This is the real goal.**

If successful, **S73** can explore a custom `scx_archimation` built from `scx_layered`'s template:
- Layer 1: `trust.slice` — tight latency, P-core priority.
- Layer 2: `game.slice` — LAVD-style virtual deadlines, P-core preference, shortest time-slice.
- Layer 3: `pe-compat.slice` (non-game PE apps) — bpfland-style cache affinity.
- Layer 4: `ai-daemon.slice` — shorter time-slice (latency) + P-core affinity.
- Layer 5: `ai-cortex.slice` — longer time-slice (throughput) + **E-core pin**.
- Layer 6: `observer.slice` — default + CPU quota 2-10%.

That is "a scheduler tuned specifically for our workload" the research brief asked about. But we do not write it in S72 — we validate that sched_ext is the right venue for it first, with LAVD as the off-the-shelf stand-in.

---

## 9. Cited kernel commits & threads

- **EEVDF merge:** Peter Zijlstra, "sched: EEVDF using latency-nice" ([lore.kernel.org](https://lore.kernel.org/lkml/20230321160458.GB2273492@hirez.programming.kicks-ass.net/t/)) → merged 6.6 ([Phoronix Linux-6.6-EEVDF-Merged](https://www.phoronix.com/news/Linux-6.6-EEVDF-Merged)).
- **EEVDF completion:** Linux 6.12 ([Phoronix Linux-Completing-EEVDF](https://www.phoronix.com/news/Linux-Completing-EEVDF), [heise 6.12](https://www.heise.de/en/news/Linux-6-12-Scheduler-now-expandable-and-EEVDF-conversion-complete-9949941.html)).
- **sched_ext merge:** Tejun Heo, "[PATCHSET v6] sched: Implement BPF extensible scheduler class" ([LKML](https://lkml.org/lkml/2024/5/1/564)) → merged 6.12 ([Phoronix Linux-6.12-Lands-sched-ext](https://www.phoronix.com/news/Linux-6.12-Lands-sched-ext)).
- **sched_ext cgroup sub-scheduler (6.19 / 7.1):** [LKML 2026/2/24/2153](https://lkml.org/lkml/2026/2/24/2153).
- **Intel cluster scheduling:** Tim Chen/Chen Yu series ([Phoronix Intel-Hybrid-CPU-Cluster-Sched](https://www.phoronix.com/news/Intel-Hybrid-CPU-Cluster-Sched)); hybrid cluster sched re-enabled 6.6 ([Phoronix Linux-6.6-EEVDF-Merged](https://www.phoronix.com/news/Linux-6.6-EEVDF-Merged) "Intel Hybrid Cluster Scheduling Re-Introduced").
- **Intel HFI / Thread Director:** Kernel docs [arch/x86/intel-hfi.html](https://docs.kernel.org/arch/x86/intel-hfi.html); Alder Lake 5.18 ([Tom's Hardware](https://www.tomshardware.com/news/intel-thread-director-coming-to-linux-5-18)); classes-of-tasks ([Phoronix Intel-Linux-Classes-Of-Tasks-TD](https://www.phoronix.com/news/Intel-Linux-Classes-Of-Tasks-TD)).
- **Hybrid-capacity scaling (Lunar/Arrow):** Intel P-State tuning for Lunar Lake ([LWN 968408](https://lwn.net/Articles/968408/)).
- **amd-pstate preferred core:** v10 patchset ([Patchew v10](https://patchew.org/linux/20231030063403.3502816-1-li.meng@amd.com/20231030063403.3502816-7-li.meng@amd.com/)) merged 6.9 ([Phoronix AMD-P-State-Preferred-Core-69](https://www.phoronix.com/news/AMD-P-State-Preferred-Core-69)); kernel doc [admin-guide/pm/amd-pstate.html](https://docs.kernel.org/admin-guide/pm/amd-pstate.html).
- **Cache-aware scheduling (AMD X3D, Intel):** Chen Yu/Tim Chen v4, 9950X3D benchmark ([Phoronix Cache-Aware-Balancing-v4](https://www.phoronix.com/news/Cache-Aware-Balancing-v4), [Phoronix Ryzen-9950X3D-Cache-Aware-Sched](https://www.phoronix.com/news/Ryzen-9950X3D-Cache-Aware-Sched), [LWN 1041668](https://lwn.net/Articles/1041668/)).
- **EAS:** Kernel docs [scheduler/sched-energy.html](https://www.kernel.org/doc/html/latest/scheduler/sched-energy.html); 5.0 landing ([Arm community blog](https://community.arm.com/arm-community-blogs/b/architectures-and-processors-blog/posts/energy-aware-scheduling-in-linux)).
- **Asahi Linux EAS:** chadmed port, battery impact on M2 Air ([Phoronix Asahi-Linux-January-2024](https://www.phoronix.com/news/Asahi-Linux-January-2024)).
- **scx_lavd (LAVD scheduler):** [Igalia LPC slides](https://lpc.events/event/18/contributions/1713/attachments/1425/3058/scx_lavd-lpc-mc-24.pdf); Meta production deploy ([Phoronix Meta-SCX-LAVD-Steam-Deck-Server](https://www.phoronix.com/news/Meta-SCX-LAVD-Steam-Deck-Server), [Tom's Hardware](https://www.tomshardware.com/software/linux/facebook-deploys-the-steam-decks-linux-scheduler-across-its-data-centers-valves-low-latency-scheduler-perfect-for-managing-metas-workloads-at-massive-data-centers)).
- **scx_bpfland / scx_layered / scx_flatcg:** [github.com/sched-ext/scx](https://github.com/sched-ext/scx); [CachyOS sched-ext tutorial](https://wiki.cachyos.org/configuration/sched-ext/); [sched_ext.com example schedulers](https://sched-ext.com/docs/scheds/c).
- **Linux 6.12 kernel doc, sched_ext:** [kernel docs scheduler/sched-ext.html](https://docs.kernel.org/scheduler/sched-ext.html).
- **Snapdragon X Elite:** [Qualcomm upstream blog 2024](https://www.qualcomm.com/developer/blog/2024/05/upstreaming-linux-kernel-support-for-the-snapdragon-x-elite).

---

## 10. 400-word summary

Hybrid CPUs are now universal: Intel has run P+E topologies since 2021 (Alder Lake) and shipped three generations of Thread Director / HFI; AMD 9950X3D welds a 3D-V-Cache CCD next to a non-cached one; Apple M-series is 4-12 P-cores plus 4 E-cores; ARM DynamIQ is ubiquitous in phones and Snapdragon X Elite laptops. Windows addressed these with per-vendor scheduler patches; Linux's 2022 hybrid support lagged noticeably and was flagged openly in LWN 909611. Between 2023 and 2026 the kernel caught up and in some cases overtook Windows: EEVDF replaced CFS in 6.6 (Stoica 1995 virtual-deadline algorithm, mergequoting Peter Zijlstra), completed the transition in 6.12; Intel cluster scheduling re-enabled in 6.6 and stabilized for Arrow/Lunar Lake in 6.10-6.12; `amd_prefcore` shipped 6.9; AMD cache-aware load-balancing v4 is queued for 6.18 and shows 5-12% wins on 9950X3D cache-sensitive workloads. Asahi Linux ported Energy-Aware Scheduling to Apple M2 in 2024 and turned 6 hours of battery into 8-15. **sched_ext (SCX) merged in 6.12** (Tejun Heo / David Vernet, LKML 2024/5/1/564) and is now in Meta production running `scx_lavd` — Igalia's Steam Deck scheduler — across messaging tiers; the LAVD design shows 5.2% FPS wins on Baldur's Gate 3. For ARCHIMATION this means: **standing on mainline EEVDF + intel/amd-pstate + EAS + cache-aware balancing is the entire story on OLD hardware**; NEW hardware gets three free wins if we just hand the kernel the right hints (preferred core, HFI, cluster info) and one more if we enable SCX. Our existing 5-slice architecture (`trust`, `pe-compat`, `game`, `ai-daemon`, `observer`) already maps one-for-one onto `scx_layered`'s declarative input. The right S72 experiment is to attach `scx_lavd` to `pe-compat.slice` behind a feature flag on NEW-tier hosts and measure 1%-low FPS on three representative PE titles against Phoronix-style baselines, with EEVDF always reachable via SCX's automatic fallback. We also split `ai-cortex.slice` out of `ai-daemon.slice` and add `AllowedCPUs=<E_CORE_CPUS>` on hybrid — the cortex is exactly the kind of batch workload E-cores exist to serve. We do not write a custom scheduler in S72; we validate that sched_ext is the right venue for one in S73. Old hardware gets EEVDF and nothing else — which, given EEVDF's tail-latency wins over CFS, is already a silent free upgrade.
