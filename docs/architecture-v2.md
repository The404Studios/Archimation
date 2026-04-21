# ARCHIMATION Architecture v2 — Canonical Specification

**Document status:** synthesizer-architect deliverable, S74 post-research.
**Authors:** synthesized from the 10-agent S74 research dispatch (reports A-J
at `docs/research/s74_{a..j}_*.md`), cross-referenced against current code at
git HEAD `5013ad9` (pre-S74 checkpoint) + 9 feature agents in the working
tree.
**Supersedes:** `docs/architecture.md` (still correct on trust ontologies +
event bus; this doc is the layered-architecture + invariants update).
**Date:** 2026-04-20.
**Paper of record:** Roberts / Eli / Leelee, *Root of Authority*, Zenodo DOI
[10.5281/zenodo.18710335](https://doi.org/10.5281/zenodo.18710335), 2026-02-20.
**Source files referenced throughout:** absolute paths on the
`C:\Users\wilde\Downloads\arch-linux-with-full-ai-control\` tree.

---

## §0. Executive thesis

**One sentence.** ARCHIMATION is a **Linux-native Windows-compatibility
distribution whose authority is rooted in an in-kernel dynamic capability
machine whose proofs are cryptographically self-consuming and whose state is
biologically patterned** — a design class with no exact precedent; the closest
analogues are (a) LSM policy with per-action metabolic cost, (b)
object-capability microkernel with dynamic rather than static capabilities,
and (c) Beer's Viable System Model realised as a kernel module.

**One paragraph.** The architecture is not reducible to any single prior-art
class. It is **not an LSM** — `grep -r 'security_add_hooks|DEFINE_LSM|struct
security_hook_list' trust/kernel/` returns zero matches (confirmed
[research-J §1 comparator 8](research/s74_j_moat_landscape.md)). It is **not
a microkernel** — it runs as `trust.ko` inside the Linux kernel, not as its
own TCB. It is **not a hypervisor-rooted system** like Windows VBS or Qubes
— the root of trust is a signed module, not a separate ring. It is **not a
pure capability system** like seL4 — the primitives are dynamic (decaying
trust scores, self-consuming proofs, chromosomal inheritance), not static.
The class that fits — a *dynamic cybernetic-kernel authority machine* — has
no canonical academic name. The paper's chosen name is **Root of Authority
(RoA)**; the product's name is **ARCHIMATION**. We recommend **retaining
both**: RoA names the primitive; ARCHIMATION names the distribution built on
top. See `docs/architecture-name-decision.md` for the full justification.

---

## §1. The five layers — revised

CLAUDE.md's layer model stands. This section restates each layer with (a)
*what it is*, (b) *primitives exported upward*, (c) *events consumed from
below*, (d) *invariants*, (e) *external interface*.

### Layer 0 — Kernel: trust.ko + binfmt_pe + Linux

**What it is.** A Linux kernel module implementing the Authority Proof
Engine (APE), the chromosomal subject struct, the 6-family trust ISA
dispatcher, the Trust Regulation Core (TRC), the morphogen field, the quorum
voter, the algedonic emitter, and the TPM2-anchored self-attestation gate.
Paired with `binfmt_pe` (MZ detection) and a stock Linux kernel for
everything else (scheduler, VFS, networking, memory management, PnP, SMP).

**Primitives exported upward** (in order of architectural weight):

1. **APE proof chain** (`trust/kernel/trust_ape.c:454-568`). Per-subject
   self-consuming proof register. `consume_proof` advances
   `P_{n+1} = Hash_cfg(n)(P_n ‖ R_n ‖ SEED ‖ NONCE_n ‖ TS_n ‖ S_n)` and
   atomically zeros `P_n` under spinlock. Research-D §1.1 details the
   mechanism; research-A §2.5 shows the correspondence to von Neumann's
   1932 Process-1 measurement collapse.
2. **Chromosomal state** (`trust/include/trust_types.h:151-248`,
   `trust_chromosome.h:137-186`). 23-pair `a_segments` (behavioral) +
   `b_segments` (construction) + `sex` conformance quadrant + CRC32
   checksum. Research-E catalogs the biology-vs-metaphor status; research-B
   gives mechanism-level fidelity (2 faithful, 5 partial, 3 metaphor-only,
   3 absent of 12 checked biological mechanisms).
3. **Trust ISA** (`trust/include/trust_isa.h:58-130`). 32-bit instruction
   word, 6 families (AUTH/TRUST/GATE/RES/LIFE/META) + VEC + FUSED,
   GPU-dispatch model with 64-bit tagged operands. Research-F analyses the
   stored-program vs homoiconic axis and reaches **reject homoiconic**;
   keep the ISA as a stored-*metadata* machine.
4. **Trust Regulation Core (TRC)** (`trust/kernel/trust_authz.c:61`).
   Token economy with 8.8 fixed-point cost multiplier and per-action decay.
5. **Morphogen field** (`trust/kernel/trust_morphogen.c:186-243`, S74
   agent 5). 32×32 reaction-diffusion grid over (activator, inhibitor);
   spatial placement of subjects.
6. **Quorum voter** (`trust/kernel/trust_quorum.c`, S74 agent 8).
   23-replica majority check *within* a single subject — detects
   uncorrelated bit-flip but provides **zero defense against kernel-write
   adversaries** (research-G §0 is the honest verdict).
7. **Algedonic channel** (`trust/kernel/trust_algedonic.c:253`, S74 agent).
   Kernel-side ring-buffer miscdevice `/dev/trust_algedonic` emitting
   severity-tagged distress packets. **The kernel emits into a void —
   there is no userspace reader** (research-C §1 and research-H §1.5
   converge on this).
8. **Self-attestation** (`trust/kernel/trust_attest.c:1-439`, S72 γ).
   TPM2 PCR-11 verification at `trust_init()`. Three modes: HARDWARE,
   SOFTWARE, FAILED.

**Events consumed from below.** None by design — Layer 0 is the bottom.
Hardware RNG (Linux CRNG post-5.17, ChaCha20-based), hardware TPM chip, CPU
instruction-error traces via kprobes, wall-clock + monotonic time.

**Invariants** (machine-checkable where indicated):
- **I-K1:** `dispatch_table[FAMILIES][OPCODES]` must be
  `const __ro_after_init`. **CURRENTLY VIOLATED** at
  `trust/kernel/trust_dispatch.c:1293` — declared `static ... = {...}` with
  no `const` + no `__ro_after_init`. Research-F §0 is the citation; this is
  a W^X gap (Finding #4 in §4).
- **I-K2:** APE proof is zeroed on read under spinlock. Holds
  (`trust_ape.c:486-488`, research-D §1.1).
- **I-K3:** Chromosome CRC32 is recomputed on every mutating operation.
  Holds.
- **I-K4:** Theorem counters at `/sys/kernel/trust_invariants/` are
  monotonically non-decreasing. Holds; counters have **never been observed
  non-zero under clean load** (research-J §3.3 flags this as the largest
  gap between "asserted" and "demonstrated").
- **I-K5:** The kernel never calls upward. CLAUDE.md claim; **verify with
  an adversarial test** (see §6 invariants).

**External interface.** `/dev/trust` character device with ioctl surface
(single entry point for userspace), sysfs `/sys/kernel/trust*` counters,
`/dev/trust_algedonic` ring-buffer device.

### Layer 1 — Object broker: pe-objectd

**What it is.** A Linux daemon implementing Windows-style named objects
(handles, events, mutexes, semaphores, jobs, sections), a registry hive,
a device namespace, and a session manager.

**Primitives exported upward.**
- Cross-process object handles with Win32 semantics
- Registry key/value store (HKLM, HKCU, HKCR with HKCR fallback to HKLM +
  HKCU per S65 A3)
- Named section objects (memfd-backed)
- Job objects (cgroup v2-backed)
- Waitable timers (timerfd-backed)

**Events consumed from below.** Optional sync events from trust.ko when
object creation/destruction crosses an authority band.

**Invariants.**
- **I-O1:** Every named object has exactly one owning trust subject at any
  time (multi-ownership goes through DUPLICATE_HANDLE with explicit ref
  increment).
- **I-O2:** Registry writes invoke `trust_gate()` on HKLM, HKCR writes; HKCU
  is subject-local.

**External interface.** Unix domain socket `/run/pe-objectd/broker.sock`.

### Layer 2 — PE runtime: pe-loader + 37+ DLL stubs

**What it is.** A user-mode PE binary loader with import resolution, TLS
callbacks, SEH, VEH, fiber support, and 37+ `.so` DLL stubs
(kernel32, ntdll, user32, gdi32, ole32, etc.). Research-B §12
observes this is structurally **bacterial
transformation** — foreign DNA (Windows .exe) taken up through a competence
system (binfmt_misc) and integrated (IAT patching) — this framing is the
paper's load-bearing biological claim that currently goes unarticulated.

**Primitives exported upward.**
- PE image loading + mapping
- IAT resolution against `.so` stubs
- Syscall interception via DLL-stub jumps
- SEH/VEH exception dispatching
- Per-PE trust subject creation at load time

**Events consumed from below.**
- `TRUST_ACTION_LOAD_PE` from `trust_gate()` at load time
- Per-subject authority decisions via `/dev/trust`
- Algedonic alarms (not yet consumed — see §4 Finding #1)

**Invariants.**
- **I-PE1:** Every PE process runs under an owning trust subject. Holds.
- **I-PE2:** An unimplemented API call MUST emit `PE_EVT_UNIMPLEMENTED_API`
  (`pe-loader/loader/pe_import.c:743` confirms). Holds.
- **I-PE3:** An unhandled SEH exception MUST emit `PE_EVT_EXCEPTION`.
  **CURRENTLY VIOLATED** — the event code exists in
  `pe-loader/include/eventbus/pe_event.h:47` but grep for
  `pe_event_emit(PE_EVT_EXCEPTION` returns zero matches (research-C §0).

**External interface.** `execve()` on an MZ-prefix binary via
`binfmt_misc`; `ptrace` for debugging; `LD_PRELOAD` for
`libtrust_wine_shim.so` (proposed in research-J §5 proposal B).

### Layer 3 — Service fabric: scm-daemon + wdm_host.ko

**What it is.** A Windows Service Control Manager implementation with
topological sort, restart policies, and dependency graphs. Plus `wdm_host`
kernel module for optional Windows driver hosting (gated, skeleton only).

**Primitives exported upward.**
- Service lifecycle (START, STOP, PAUSE, CONTINUE, QUERY_STATUS)
- svchost-style SHARE_PROCESS grouping (S65 A4, 840 LOC)
- Kernel driver load (refuse-by-default; research-J §3.3 is explicit that
  the 30-40% completeness is aspirational)

**Events consumed from below.**
- Service state changes from per-service trust subjects
- Driver-load denials from `TRUST_ACTION_LOAD_KERNEL_BINARY`

**Invariants.**
- **I-S1:** No service starts unless its dependencies are all RUNNING.
- **I-S2:** A kernel-mode driver load must produce either a TRUST_ALLOW or
  TRUST_DENY verdict (no silent SERVICE_RUNNING lies — post-S65 A1, per
  `memory/session65_10agent_native_implementation.md`).

**External interface.** LP-JSON over Unix socket; Windows `sc.exe`-style CLI.

### Layer 4 — AI cortex

**What it is.** A Python/FastAPI daemon on port 8420 hosting observers
(trust_observer, memory_observer, entropy_observer, assembly_index),
an active-inference cortex (S74 agent 6), a decision engine, an event bus,
and an autonomy controller. Plus LLM integration (veto-only, per
`docs/architecture.md:§3`).

**Primitives exported upward.**
- Event-bus subscription API
- `/cortex/*` HTTP endpoints for external orchestration
- `trust_action_cognitive_feedback()` ioctl back to kernel (proposed for
  S75; not yet wired — research-E §3 flags this as the autopoietic gap)

**Events consumed from below.**
- All layers via event bus (NDJSON over Unix socket at
  `/run/pe-compat/events.sock`)
- `/sys/kernel/trust_invariants/` counters via polling
- **SHOULD consume** `/dev/trust_algedonic` — does not
  (the producer-without-consumer gap, Finding #1).

**Invariants.**
- **I-C1:** The cortex is **veto-only**. CLAUDE.md claim; research-J §3.3
  notes this is **not mechanically enforced** — "a malicious cortex could
  call `trust_action` as easily as `trust_veto`." Needs typestate audit
  before defensible.
- **I-C2:** LLM cannot originate actions. Holds
  (`cortex/decision_engine.py` pipeline order).
- **I-C3:** Autonomy below SOVEREIGN prevents cortex self-modification.
  Holds by design (`autonomy.py:32-43`) — and research-H §1.2 notes this
  means the system is **definitionally allopoietic under Rosen's
  criterion**. That's a deliberate security choice, not a bug.

**External interface.** `http://localhost:8420/` FastAPI; `/dev/trust`
ioctl (downward); event-bus socket (upward subscribe).

---

## §2. Cross-cutting primitives

Primitives that don't belong to any single layer but are referenced across
multiple layers. Each section: **defining layer**, **consuming layers**,
**lifecycle**, **thread-safety**, **failure mode**.

### §2.1 APE proof chain

- **Defining layer:** 0 (`trust/kernel/trust_ape.c`).
- **Consuming layers:** all. Layer-1 SCM calls it on service start;
  Layer-2 PE loader calls it on binary load; Layer-3 on driver load;
  Layer-4 never directly (cortex is a subscriber only).
- **Lifecycle:** created at `trust_ape_create_entity()` on subject birth;
  advanced on every `consume_proof` call; destroyed on
  `trust_ape_destroy_entity()` at subject death. See
  research-D §1.1 for the complete state machine.
- **Thread-safety:** two-level spinlock (`g_trust_ape.lock` + per-entry
  `entry->lock`), drop global after find, operate under per-entry. Atomic
  read-and-zero. Non-sleeping.
- **Failure mode:** `chain_broken = 1` flag on crypto-API failure. Once set,
  the chain is permanently dead; subject authority is zeroed. This is the
  **security hardening** research-B §2 flags — do NOT add "excise and
  retry" even though real DNA-polymerase proofreading does.

### §2.2 Trust ISA

- **Defining layer:** 0 (`trust/include/trust_isa.h`,
  `trust/kernel/trust_dispatch.c`).
- **Consuming layers:** 0 (dispatch); 1-3 indirectly via the `/dev/trust`
  ioctl.
- **Lifecycle:** the ISA is static — defined at build time, frozen at
  module load. No runtime mutation of the dispatch table (or at least:
  **this is the invariant we want**; currently the table is mutable,
  Finding #4).
- **Thread-safety:** dispatch is non-blocking per instruction; multi-op
  batches take the subject lock.
- **Failure mode:** unknown opcode → return TRUST_ERR_BAD_OPCODE, increment
  stats counter.

### §2.3 Chromosomal state

- **Defining layer:** 0 (`trust/include/trust_chromosome.h`,
  `trust/kernel/trust_chromosome.c`).
- **Consuming layers:** 0 (authz checks, quorum, morphogen placement);
  Layer 4 observers read via `/dev/trust`.
- **Lifecycle:** born with `trust_subject_create`, runtime-A segments
  updated on every syscall (`trust_chromosome_update_a`), B segments at
  construction + rare rotation events, terminated at apoptosis.
- **Thread-safety:** TLB slot spinlock.
- **Failure mode:** CRC32 mismatch → `TRUST_IMMUNE_SUSPICIOUS`; chromosome
  unexpectedly "sex YY" → apoptosis candidate. Research-E §3.6 points out
  that "XY" naming is metaphor overclaim — rename to `conformance_quadrant`
  recommended but not required for correctness.

### §2.4 Morphogen field

- **Defining layer:** 0 (`trust/kernel/trust_morphogen.c`, S74 agent 5).
- **Consuming layers:** 0 (authz can query field state); Layer-4 is a
  potential consumer but not wired.
- **Lifecycle:** initialized at module load; persists across subject birth/
  death; per-cell state survives.
- **Thread-safety:** per-row spinlock; 4 Hz RD tick via kernel timer.
- **Failure mode:** allocation failure at init → feature absent, authz
  falls back to non-spatial path.

### §2.5 Quorum voter

- **Defining layer:** 0 (`trust/kernel/trust_quorum.c`, S74 agent 8).
- **Consuming layers:** 0 (authz fast-path on critical fields).
- **Lifecycle:** stateless per-call; no memory allocation.
- **Thread-safety:** deterministic, non-allocating, safe on the authz
  fast-path per `trust/include/trust_quorum.h:15-16`.
- **Failure mode:** sysfs registration failure → voting still works,
  counters absent. **The real failure mode is architectural**: the 23
  replicas are in one struct; a kernel-write adversary flips all 23.
  Research-G §0 is the honest verdict — this is a **crash/bit-flip
  integrity witness**, NOT Byzantine fault tolerance.

### §2.6 Algedonic channel

- **Defining layer:** 0 (`trust/kernel/trust_algedonic.c`, S74 agent) +
  `/dev/trust_algedonic` miscdevice.
- **Consuming layers:** NONE currently. Should be Layer 4
  (`ai-control/daemon/algedonic_reader.py`, ~120 LOC, not yet written —
  Finding #1).
- **Lifecycle:** ring buffer on module load; writes from IRQ-context paths;
  readers open `/dev/trust_algedonic` and block on `read()`.
- **Thread-safety:** IRQ-safe emit; blocking reads.
- **Failure mode:** buffer overflow drops old packets; counter increments.

### §2.7 Active-inference generative model

- **Defining layer:** 4 (`ai-control/cortex/active_inference.py`, S74 agent 6).
- **Consuming layers:** Layer 4 only (decision engine pulls action
  selections).
- **Lifecycle:** initialised on daemon start; updated per-tick from
  observer events; persisted to `/var/cache/cortex/beliefs.pkl.zst`
  periodically.
- **Thread-safety:** GIL-protected Python; single-reader model per subject.
- **Failure mode:** Dirichlet posterior saturation → uniform prior fallback;
  predicate-error spike → algedonic-injection (planned S75, not wired).

### §2.8 Event bus

- **Defining layer:** 4 (`ai-control/cortex/event_bus.py`).
- **Consuming layers:** 0-4 as publishers; 4 + external orchestration as
  subscribers.
- **Lifecycle:** singleton, daemon-lifetime.
- **Thread-safety:** asyncio queue; single-writer per channel.
- **Failure mode:** buffer overflow is lossy — events are advisory per
  `docs/architecture.md:§4`. Security-critical gating lives in Layer 0.

---

## §3. Data flow diagram

```
                      L4   AI CORTEX
                ┌─────────────────────────────┐
                │ active_inference  <─ pull ──┤ observer events (bus)
                │      │                      │
                │      │ select_action()      │
                │      ▼                      │
                │ autonomy_controller ────────│
                │      │                      │
                │      │ /dev/trust ioctl     │
                │      ▼                      │
                └──────┼──────────────────────┘
                       │
 ALGEDONIC FAST-PATH   │   COMMAND FLOW (downward)
 (L0 --> L4 bypass)    │                            SELF-ATTEST LOOP
      ┌────────────┐   │                            (L0 --> L0 startup)
      │  "pain"    │   │                                 ┌───────┐
      │   event    │   │                                 │ TPM2  │
      │            │   ▼                                 │ PCR11 │
      │            │  L3   SERVICE FABRIC                └───┬───┘
      │            │ ┌─────────────────────────────┐        │
      │            │ │ scm-daemon                  │        │
      │            │ │ wdm_host.ko (skeleton)      │        │
      │            │ └─────────────────────────────┘        │
      │            │        │                               │
      │            │        │                               │
      │            │        ▼                               │
      │            │ L2   PE RUNTIME                        │
      │            │ ┌─────────────────────────────┐        │
      │            │ │ pe-loader + 37 DLL stubs    │        │
      │            │ │ SEH / VEH / TLS             │        │
      │            │ └─────────────────────────────┘        │
      │            │        │                               │
      │            │        │                               │
      │            │        ▼                               │
      │            │ L1   OBJECT BROKER                     │
      │            │ ┌─────────────────────────────┐        │
      │            │ │ pe-objectd                  │        │
      │            │ │ named objects, registry     │        │
      │            │ └─────────────────────────────┘        │
      │            │        │                               │
      │            │        │                               │
      │            │        ▼                               │
      │            │ L0   KERNEL                            │
      │  ┌─────────┼──────────────────────────────┐         │
      │  │ trust.ko (APE + chromo + ISA + TRC +   │<────────┘
      │  │   morphogen + quorum + algedonic +     │  trust_attest_init()
      │  │   self_attest + lifecycle)             │  reads PCR 11
      │  │   ▲     │                              │  PCR11 mismatch -> refuse init
      │  │   │     │                              │
      │  │   │     │ dispatch_table[F][O]         │
      │  │   │     │                              │
      │  │ ┌─┴─────┴───────┐                      │
      │  │ │ g_trust_ape   │ (per-subject state)  │
      │  │ └───────────────┘                      │
      │  └────────────────────────────────────────┘
      │      │                         ▲
      │      │ emit                    │ read (NONE, currently)
      │      ▼                         │
      └─ /dev/trust_algedonic ─────────┘  <-- FINDING #1 GAP

              EVENT FLOW (upward)                 COMMAND FLOW (downward)
              ----------------                    ----------------------
              per-layer emit           cortex veto via ioctl
              event bus aggregates     SCM start/stop
              observers/cortex consume loader load
                                       kernel authz check
```

**Three loops are load-bearing.**

1. **Command loop (downward + fast-path upward):** Layer 4 → Layer 0
   ioctl → verdict → ALLOW/DENY → back up to L4. Fast.
2. **Event loop (upward):** L0/L1/L2/L3 emit → event bus → L4 observers →
   active_inference updates belief state. Loose, lossy, advisory.
3. **Algedonic bypass (L0 → L4 with no intermediates):** kernel writes
   `/dev/trust_algedonic`; cortex SHOULD read; currently the read side
   is absent. Closing this is Finding #1.
4. **Self-attestation loop (L0 → L0 at startup):** `trust_attest_init()`
   reads TPM PCR 11, compares against expected; mismatch → `return
   -EIO` from module init. Healthy but not used at runtime.

---

## §4. The 12 convergent findings

Ten research agents independently reviewed architecture, biology,
cryptography, reliability, observation, bisimulation, moat landscape,
etc. The following findings emerged where ≥2 independent agents
converged on the same observation. Status column is the operational
recommendation; owner axis identifies which research agent's report
provides the detailed prescription.

| # | Finding | Research agents converging | Implication | Status: fix in S74 / S75 / documented-only | File / line evidence |
|---|---|---|---|---|---|
| 1 | **Kernel algedonic producer, zero userspace consumer.** Kernel emits into `/dev/trust_algedonic`; no process reads it. | H (§1.5), C (§0.2 top-3 item #1) | Active data loss; kernel cycles into void; autopoietic closure broken (Maturana-Varela) + VSM algedonic principle defeated (Beer). | **S74 fix via agent 10** (~130 LOC: `ai-control/daemon/algedonic_reader.py`). | `trust/kernel/trust_algedonic.c:253` (emitter); `grep algedonic ai-control/cortex/*` returns 0 reader hits; `ai-control/cortex/active_inference.py` references only the *concept*, not the device. |
| 2 | **APE is the genuinely-novel primitive (behavioral-state binding).** No cryptographic primitive in the literature binds proof advancement to behavioral fingerprint. | A (§2.5), B (§1 Finding 1), D (§3.1), J (§3.1) | The paper's defensible peer-review claim is NOT the chain (Lamport 1981, Double Ratchet 2016 are ancestors). It IS the behavioral-state entanglement via `S_n = chromosome_checksum`. | Document; stop understating in publicity/README. No code change needed. | `trust/kernel/trust_ape.c:454-568` (the construction); `trust_ape.h:7-35` (the formula with S_n). |
| 3 | **"Meiosis" has 0/5 essential biological properties.** Our `trust_meiosis()` is anonymized dominant-parent selection + per-meiosis SHA-256 blinding. Real meiosis has S-phase, homolog pairing, Holliday junctions, reductional division, 4 haploid products. | B (§3), E (§4 — side-by-side comparison table), A (§2.5 analogously for APE but for Process-1 not meiosis) | Metaphor-only label. A biologist peer-reviewer of the paper would reject the "meiosis" claim on first pass. | Rename to `trust_dual_authority_bond()` OR paper disclaimer. 0 LOC of mechanism change; ~200 LOC for renaming + backward-compat shim. | `trust/kernel/trust_meiosis.c:237-448`; function comment at :1-9 already admits ambiguity ("entirely distinct from legacy trust_lifecycle_meiotic_combine"). |
| 4 | **`dispatch_table[FAMILIES][OPCODES]` is NOT const, NOT __ro_after_init.** | F (§0 ground truth, §7), J (§3.3) | W^X gap. A kernel-write primitive (CVE in any LSM, driver, or trust.ko itself) could flip handler pointers and collapse the authority graph. | **S74 fix via agent 10** (~40 LOC: add `const`, `__ro_after_init`, struct layout review). | `trust/kernel/trust_dispatch.c:1293` — declared `static trust_cmd_handler_t dispatch_table[TRUST_STAT_FAMILY_SLOTS][TRUST_CMD_MAX_OPCODES] = {...};` with no `const`, no `__ro_after_init`. Verified via direct grep. |
| 5 | **7 paper theorems have never been adversarially exercised.** sysfs counters sit at 0 under clean load and have never flipped. | D (§1.5, §3.3), G (§0, §2.3), J (§3.3) | Validation is structural only, not runtime. Peer reviewers of the Zenodo paper will push on this hardest. | **S75 highest-ROI** (~800 LOC harness, `tests/adversarial/theorem_violation_suite.py`). 8 test classes, one per theorem. Research-J §5 Proposal A is the detailed design. | `trust/include/trust_theorems.h:5-6` (paper citation); `trust/kernel/trust_invariants.c:67, 395, 414` (counter scaffolding); no corresponding `tests/adversarial/` directory. |
| 6 | **Producer-without-consumer is a structural pattern, not a one-off.** | C (§0, §4 all four channels), H (§1.5 algedonic, §1.4 differential observer missing) | At least 4 channels currently have no consumer: (a) `/dev/trust_algedonic`, (b) 4 mitokine channels that don't exist at all, (c) `PE_EVT_EXCEPTION` is defined at `pe_event.h:47` but never emitted, (d) PE stress aggregate signals absent. | Document as an architectural anti-pattern; every new channel must name its consumer at PR time. New invariant in §6 below. | `pe-loader/include/eventbus/pe_event.h:47` (`PE_EVT_EXCEPTION` declared, zero emit sites). |
| 7 | **Monte Carlo is absent from `cortex/`.** Decision engine is entirely Markov-deterministic. | A (§2.6 top recommendation) | Methodological gap. Confidence calibration, rollout search, fault-injection, proof-of-work rate limiting all should be stochastic; currently all deterministic. | **S75** (~350 LOC: `ai-control/daemon/monte_carlo.py`). | `ai-control/cortex/decision_engine.py:138-303`, `active_inference.py:54`, `behavioral_markov.py` all deterministic. `grep -rni 'monte|mcmc' ai-control/` returns zero actual Monte Carlo. |
| 8 | **APE ≡ Von Neumann 1932 Process 1 measurement collapse.** Same structural move: observation destroys observed state, next state derives from observation. | A (§2.5, §3.1) | Quantum-info-theoretic framing unlocks no-cloning (Wootters-Zurek 1982) and no-broadcasting (Barnum et al. 1996) as **security theorems**. Also makes TPM self-attestation a second instance of the pattern. | Document in `docs/roa-conformance.md` (~80 LOC of prose + header comment + citation addition). 0 LOC of code change. | `trust/kernel/trust_ape.c:486-488` (the read-and-zero); von Neumann 1932 §VI for the theory. |
| 9 | **trust_quorum is CFT+, not BFT.** Kernel-write adversary flips 23-0 in one move. AND: header declares sysfs path `/sys/kernel/trust/quorum/*`, code creates `/sys/kernel/quorum`. | G (§0, §2.3, §2.4), J (§3.3) | Threat-model honesty. The 23 replicas live in one struct → NOT independent against kernel-write. Document as "integrity witness against memory corruption," NOT "Byzantine fault tolerance." | **S74 fix via agent 10** for path drift (~5 LOC); document threat-model honestly in README + paper disclaimer. **S75** if BFT semantics is desired (~500 LOC per research-G §6 for threshold signatures). | `trust/include/trust_quorum.h:48` (comment says `/sys/kernel/trust/quorum/*`); `trust/kernel/trust_quorum.c:194` (`kobject_create_and_add("quorum", kernel_kobj)` creates `/sys/kernel/quorum`, NO `/trust/` prefix). Verified via grep. |
| 10 | **94M-variant reconfigurable hash documented / 3 implemented + missing `consume_proof_v2` / `apply_reconfigurable_hash`.** | D (§3.3 — items 3, 10; §0.3 row "S74 regression flag") | **CODE HAS REGRESSED from an earlier version OR docs lie.** Header at `trust_ape.h:44-52` claims 720 × 256 × 16 × 32 = 94,371,840 configs. Shipping code at `trust_ape.c:40-45` + `trust_types.h:276` implements **three** (SHA-256, BLAKE2b-256, SHA3-256). `docs/roa-conformance.md:58-60` references `apply_reconfigurable_hash()` at `trust_ape.c:224` which **does not exist**. Peer reviewer of Zenodo paper would flag immediately. | **URGENT** — reconcile before S75. Either (a) implement the 94M configs (~300-400 LOC); (b) amend docs + paper to match 3-algo reality (~40 LOC); (c) determine if git history shows a regression and restore. **Agent 10 triages this; does not attempt bring-back.** | `trust/kernel/trust_ape.h:71, 88` (v2 declared); `trust_ape.c` is 656 LOC (no v2 defined); `trust_ape_markov.c:21` explicitly admits inability to call `apply_reconfigurable_hash`. |
| 11 | **Turing-incompleteness IS the moat (no self-emission).** | F (§0, §1, §7 explicit reject) | Architecture decision; do NOT add homoiconicity. Every trust policy is statically analyzable in bounded time precisely because no handler can emit instructions to a queue for later execution. This is the decidability-security tradeoff done RIGHT. | Document; formalize invariant in new `trust_invariants.c` check (~60 LOC): runtime assert that no handler has called `trust_isa_enqueue_for_self`. | `trust/include/trust_isa.h:58-130` (no emission opcode); `trust/kernel/trust_dispatch.c:1293` (dispatch is over userspace buffer, never over kernel-emitted queue). Research-F §1 is the full argument. |
| 12 | **Empirical bisimulation harness 680 LOC; formal proof 3-5 person-years.** | I (§0.1, §4) | Paper-to-code validation is ENGINEERING not research. We ship the empirical harness; we do NOT attempt a Sail/Isabelle proof. | **S75** (~680 LOC total: 280 Python orchestrator + 180 C trace-tap + 140 Sail/Verilator harness glue + 80 oracle diff, research-I §4 design). | `docs/research/s74_i_bisimulation.md` §4 design; no `tests/bisim/` or `formal/` directory exists yet. |

**Interpretation of the table.** Items #1, #4, #9 are S74 fixes handed to
agent 10. Item #10 is triage-before-action. Items #5, #7, #12 are the top
three S75 items (adversarial harness, Monte Carlo, bisim). Items #2, #3,
#8, #11 are documentation updates (free but high-value). Item #6 is the
architectural anti-pattern that should govern all future PRs.

---

## §5. Layer-by-layer diagnosis

For each of the five layers: (a) *confirmed-correct*, (b) *divergence from
ideal*, (c) *gap*. Citations to research reports (`RA`=research-A through
`RJ`=research-J) or code are explicit.

### Layer 0 — Kernel

**(a) Confirmed-correct.**
- APE read-and-zero semantics are rigorous; `memzero_explicit` cannot be
  optimized away (RD §1.2 confirms via compiler-contract analysis).
- TPM2 PCR-11 attestation at `trust_init()` refuses module init on mismatch
  (RD §2.18 notes this is well-wired).
- 23-pair chromosome struct matches paper byte-exactly
  (`trust/include/trust_chromosome.h` TRUST_CHR_A_COUNT, RE §0 table).
- 6-family ISA with 4-bit opcode, 4-bit flags, 16-bit immediate — stable,
  documented, consistent with `trust_cmd.h` (RF §0).
- Chi-square runtime witness for Theorem 3 exists at
  `trust_ape_markov.c` (RD §1.5) — but see divergence (b).

**(b) Divergence from ideal.**
- **Dispatch table mutable** (Finding #4). `trust/kernel/trust_dispatch.c:1293`.
  W^X is a hard invariant in modern kernel design; we're behind.
- **Chi-square witness tests SHA-256, not the composite chain.** RD §1.5
  admits openly. This is a validation gap, not a security gap — but a
  peer reviewer sees it immediately.
- **APE reconfigurable-hash regression** (Finding #10). Either code
  regressed or docs lie; ambiguity is dangerous.
- **trust_quorum sysfs path drift** (Finding #9). Minor but
  documentation-vs-reality drift.
- **Meiosis mechanism** is anonymization + dominance selection, not
  recombination (RB §3, RE §4, Finding #3).

**(c) Gap.**
- **Adversarial theorem harness** (Finding #5). Biggest credibility risk.
- **Post-compromise security in APE chain** — SEED doesn't ratchet;
  SEED compromise once means all future proofs are forgeable. RD §2.23 is
  explicit; fix is Double-Ratchet-style re-seeding every K proofs.
- **TPM RNG not mixed into SEED** — RD §3.4 concrete hardening proposal
  (~5 LOC diff).
- **Cache-line flushing after `memzero_explicit`** — RD §3.3 item 5 (L1/L2/L3
  cache retention window).
- **No `__nosave` / mlock on `g_trust_ape.entries`** — RD §3.3 item 6
  (hibernation dump risk).
- **Bennett logical depth observer** (RH §1.6) — the "deep-computed vs
  shallow-random" discriminator; currently absent.
- **Integration observer / Φ-proxy** (RH §1.7) — mutual information across
  observers; currently zero cross-observer integration measure.

### Layer 1 — Object broker

**(a) Confirmed-correct.**
- Single owner per object, registry with HKCR fallback, session mgr all
  working (S65 A3, S65 A6 per memory notes).
- Unix socket broker interface stable.

**(b) Divergence from ideal.**
- **No peer-to-peer DLL sharing (bacterial "conjugation")** — each PE
  process redoes full import resolution. RB §12 and RC §3(d) both note the
  performance + architectural gap. This is also an S65+ handoff.

**(c) Gap.**
- **Cross-PID DUPLICATE_HANDLE** — mentioned as open in
  `session66_handoffs` memory note. Still open.

### Layer 2 — PE runtime

**(a) Confirmed-correct.**
- PE32+ loading, IAT resolution, TLS, SEH, 37+ DLL stubs all functional
  (S65-S69 PE corpus testing reaches 16/18 on pkg-23 per memory notes).
- `pe_event_emit(PE_EVT_UNIMPLEMENTED_API)` emits correctly at
  `pe_import.c:743` (RC §3, RB §12 both confirm).

**(b) Divergence from ideal.**
- **PE32 (32-bit) not supported** — S70 handoff open.
- **Anti-cheat shims demoted to research** (S67 A8, memory note). Policy
  decision is "opt-in only, ban-risk accepted."

**(c) Gap.**
- **`PE_EVT_EXCEPTION` never emitted** (Finding #6). Code exists, call
  site missing. ~40 LOC fix in SEH handlers (`pe-loader/dlls/kernel32/
  kernel32_seh.c`).
- **libtrust_wine_shim** (RJ §5 Proposal B). Turns Wine's compat coverage
  into our competitive advantage by LD_PRELOAD'ing NT syscall interception
  + trust gate. ~1200 LOC.

### Layer 3 — Service fabric

**(a) Confirmed-correct.**
- SCM with topo sort, restart policy, dep graph (S65 A4, 840 LOC).
- svchost SHARE_PROCESS grouping (S65 A4).
- Honest kernel-driver load: no more lying `SERVICE_RUNNING` (S65 A1
  refactor).

**(b) Divergence from ideal.**
- **Tier 3 (drivers) at 30-40%** per paper-validation memo. Aspirational.
  RJ §3.3 is explicit: "a real-world .sys driver would oops."

**(c) Gap.**
- **First-party WDM driver shipped under trust gate** — RJ §5 would be
  the moat-widening move if achievable (currently no WDM driver is in
  scope).

### Layer 4 — AI cortex

**(a) Confirmed-correct.**
- Observers (trust, memory, entropy, assembly) emit per-tick structured
  events (S74 agents 5-9).
- active_inference.py with Dirichlet generative model, EFE action selection
  (S74 agent 6).
- Event bus with NDJSON schema v2 (S44 A6 per `architecture.md:§4`).
- LLM is veto-only per pipeline order (`decision_engine.py`).

**(b) Divergence from ideal.**
- **cortex is veto-only *by convention, not enforcement*** (I-C1, Finding
  #6 analogue). RJ §3.3 flags this; typestate audit outstanding.
- **Autopoietic closure is one-way** (RE §3.4) — observer → cortex loop
  works, but no `TRUST_ACTION_COGNITIVE_FEEDBACK` ioctl back. RI §4
  framework calls this "half-wired."

**(c) Gap.**
- **Algedonic reader** (Finding #1).
- **Library census observer** (RH §1.1) — subject counts by DLL/library
  name are absent; current census is keyed on immune/risk/sex axes only.
  ~180 LOC.
- **Self-model (meta_cortex)** (RH §1.2) — cortex does not observe itself.
  Partial Rosen closure gap; ~250 LOC.
- **Differential observer (Bateson filter)** (RH §1.4) — observers mostly
  publish absolute values not deltas. ~150 LOC.
- **Monte Carlo module** (Finding #7). ~350 LOC.

---

## §6. Invariants that make this architecture

An architecture is not a list of features — it is a list of invariants that
every feature must preserve. The following are the candidate invariants; we
state each, cite the research reports that argue for it, and mark whether
it is currently machine-checked, eyeball-checked, or merely aspirational.

### I-1: Turing-incompleteness of trust ISA (no self-emission)

**Statement.** No trust ISA handler may emit a trust instruction to a queue
for later execution by the kernel. The instruction stream is strictly
userspace-to-kernel one-way.

**Citation.** RF §0, §1, §7. This is the explicit *reject* of
homoiconicity; the decidability-security tradeoff done right.

**Enforcement today.** Eyeball only; no runtime check. `grep trust_isa_enqueue`
returns no matches in kernel/, but there is no machine invariant that
prevents a future handler from adding one.

**How to strengthen (~60 LOC).** Runtime assert in `trust_invariants.c`:
every handler's stack frame must not have called any function whose symbol
matches `trust_isa_enqueue_*` or `trust_dispatch_*_reenter`. Dynamic check
via function-address heuristic. Weak but visible.

### I-2: Monotonic authority decay / Hayflick-limit equivalent

**Statement.** `S(child) < S(parent)` for mitotic spawn. `S(shared) ≤ min(S_A,
S_B)` for meiotic join. Theorem 4 in the paper.

**Citation.** RE §5.1 — biological analogue is telomere shortening /
Hayflick limit; RB §2 — the security property is strictly stronger than
the biology.

**Enforcement today.** `check_mitosis` and `check_meiosis` sysfs counters in
`trust_invariants.c:67`. **Never observed non-zero under clean load** — the
check works; an adversarial harness is needed to see it fire (Finding #5).

### I-3: Cortex-veto-only

**Statement.** The cortex may reject a proposed action but may not
originate one.

**Citation.** `docs/architecture.md:§3`, CLAUDE.md.

**Enforcement today.** Eyeball + pipeline order in
`cortex/decision_engine.py`. **Not typestate-enforced** (RJ §3.3). A
malicious cortex could call `trust_action` directly.

**How to strengthen (~80 LOC).** Python typestate: decorate veto-only
methods with `@veto_only`; decorate `trust_action` as
`@requires_capability(Capability.ORIGINATE)` which the cortex does not
have. Add runtime check. At kernel side: separate `/dev/trust_cortex`
device that only accepts veto ops.

### I-4: Destroy-on-read for APE proofs

**Statement.** `trust_ape_consume_proof` atomically reads and zeros the
proof register before returning.

**Citation.** RD §1.2, RA §2.5.

**Enforcement today.** Verified at `trust_ape.c:486-488`;
`memzero_explicit` + `proof_valid = 0` under spinlock. Strongest
machine-checked invariant in the codebase.

**Note.** RD §3.3 item 5 notes the memzero is rigorous on the field but
does NOT flush cache lines; a Flush+Reload attacker could potentially
recover from L1/L2/L3. Hardening is a `CLFLUSHOPT` addition.

### I-5: Kernel never calls upward

**Statement.** Layer 0 (trust.ko) makes no calls to Layer 1, 2, 3, or 4.
Upward communication is only via event bus + algedonic channel, which are
"fire and forget" — no response semantics.

**Citation.** CLAUDE.md, `architecture.md:§1`.

**Enforcement today.** Eyeball only. Kernel code has `pr_info`, `pr_warn`,
etc. but no RPC upward. No known violations.

**How to strengthen.** Build-time lint: `grep -r 'call_usermodehelper\|
socket.*AF_UNIX' trust/kernel/` and fail CI if any match. Already the case
at this HEAD.

### I-6: Every producer must have a consumer (new — S74 anti-pattern)

**Statement.** Any event channel, counter, device file, or published signal
must name at least one in-tree consumer at the time it is merged.

**Citation.** Finding #6 — RC §0, RH §1.5 converge; RC §3(c) generalizes
to 4 current violations.

**Enforcement today.** Does not exist. This finding proposes it as a new
invariant.

**How to strengthen.** PR-template checklist: every new emit site must
reference the consumer file:line. CI grep: for every `pe_event_emit`,
`algedonic_emit`, sysfs counter creation, corresponding read site must
exist. Build fails on broken producers.

### I-7: Turing-incomplete ISA enforced by build-time proof

Candidate new invariant: make I-1 machine-checkable at build time via a
static-analysis pass that enumerates all handlers and verifies none takes
an `instruction_word*` argument (i.e., all handlers operate on already-
decoded operands, never on raw encoded instructions).

**Citation.** RF §7.

**Current enforcement.** None. Aspirational.

---

## §7. Proposed architecture name — or retention

We arrive at **three legitimate naming options**. See
`docs/architecture-name-decision.md` for the full justification; summary
here:

**Option 1 (recommended): Retain "Root of Authority (RoA)" for the primitive
+ "ARCHIMATION" for the distribution.**

- RoA names the mathematical object (APE + chromosome + ISA + TRC +
  morphogen + quorum + algedonic + attest + invariants). The paper already
  uses this name.
- ARCHIMATION names the product (Arch Linux ISO + bootc image + PE runtime
  + AI daemon + desktop).
- No prior art collision confirmed (RJ §5 did not flag either).

**Option 2: "Cybernetic Authority Kernel" (CAK).**

- Descriptive; emphasizes Beer VSM + kernel. But "cybernetic" is an
  academic word; doesn't sell; and existing systems (e.g. Genode's Cybersec
  Mention) may have it.
- Risk: too academic for a distro.

**Option 3: "Dynamic Capability Kernel" (DCK).**

- Contrasts with seL4's static capabilities. Technically accurate.
- But "dynamic capabilities" already denotes something else in microkernel
  literature (Eros, KeyKOS — see Coyotos successors).

**Reject:** "Biological OS" (name-vs-mechanism gap per RE §3-§5 makes this
indefensible), "Cognitive OS" (overclaims the LLM's role per
`architecture.md:§3`), "Self-Consuming OS" (single-feature naming).

**Final recommendation: Option 1.** The paper is named; the product is
named; both are unused elsewhere; changing either would cost readers more
than it gains.

---

## §8. The punch list — what's currently broken vs. the ideal

Ordered by priority. Priority = (a) blocks something critical NOW × (b)
blocks external credibility × (c) would defeat a reasonable threat.

| Prio | Item | Category | Effort | Owner |
|------|------|----------|--------|-------|
| 1 | **Algedonic reader** (Finding #1) — L0 emits, L4 consumes nothing | Blocks NOW (kernel cycling into void) | ~130 LOC | S74 agent 10 |
| 2 | **W^X on dispatch_table** (Finding #4) — kernel-write adversary trivial moat collapse | Blocks credibility + threat | ~40 LOC | S74 agent 10 |
| 3 | **APE regression triage** (Finding #10) — docs claim 94M configs, code has 3 | Blocks credibility (paper peer review) | Investigation only, no code | S74 agent 10 |
| 4 | **trust_quorum sysfs path drift** (Finding #9) — header vs code disagree | Small but embarrassing | ~5 LOC | S74 agent 10 |
| 5 | **PE_EVT_EXCEPTION never emitted** (Finding #6) — producer-without-consumer instance | Observability loss | ~40 LOC | S75 |
| 6 | **Adversarial theorem harness** (Finding #5) — 7 theorems never fire | Blocks credibility HARD | ~800 LOC | S75 |
| 7 | **Monte Carlo module** (Finding #7) | Methodological gap for rollout + calibration | ~350 LOC | S75 |
| 8 | **Bisimulation empirical harness** (Finding #12) — FPGA↔kernel validation | Paper claim depends on this | ~680 LOC | S75 |
| 9 | **Meiosis naming** (Finding #3) — metaphor overclaim | Credibility with biologists | ~200 LOC + paper disclaimer | S75 |
| 10 | **Cortex typestate enforcement** (I-C1 gap) — veto-only not mechanical | Threat (malicious cortex) | ~80 LOC | S75 |
| 11 | **APE chain post-compromise security** — SEED ratcheting | Defense-in-depth | ~150 LOC | S75-S76 |
| 12 | **TPM RNG mixed into APE SEED** (RD §3.4) | Defense-in-depth | ~20 LOC | S75 |
| 13 | **Library census observer** (RH §1.1) — cross-process DLL histogram | Cortex signal depth | ~250 LOC | S75 |
| 14 | **Bennett logical depth observer** (RH §1.6) — ransomware vs video encoder | Cortex signal depth | ~110 LOC | S75-S76 |
| 15 | **Self-model (meta_cortex)** (RH §1.2) — Rosen R-loop | Autopoietic completeness | ~280 LOC | S76 |
| 16 | **Differential observer (Bateson filter)** (RH §1.4) | Cortex signal quality | ~150 LOC | S76 |
| 17 | **Integration observer / Φ-proxy** (RH §1.7) — cross-observer MI | Cortex signal quality | ~200 LOC | S76 |
| 18 | **libtrust_wine_shim** (RJ §5 B) — trust-gate the Wine syscall layer | Moat-widening | ~1200 LOC | S76-S77 |
| 19 | **Hierarchical predictive coding** (RH §1.8) — cortex depth | Cortex maturity | ~300 LOC | S77+ |
| 20 | **Analog amplitude rail** (RA §2.9) — 16 extra bits of trust precision | Out of 8.8 fp saturation | ~200 LOC | S77+ |
| 21 | **VN mean ergodic witness** (RA §2.4) — convergence rate metric | Observability maturity | ~120 LOC | S77+ |

---

## §9. Moat-widening moves from research J (placed in architecture)

Research-J identified 5 concrete moat-widening proposals. Here is their
placement in the layered architecture:

- **Proposal A — Adversarial Theorem Harness (T1–T7).** Sits at the
  test/validation edge of every layer. Specifically:
  - T1-T3 exercise Layer 0's APE
  - T4 exercises Layer 0's chromosome + Layer 3's mitotic spawn
  - T5 exercises Layer 0's revocation (cross-layer)
  - T6 exercises Layer 0's TRC + Layer 3's per-service throughput
  - T7 exercises Layer 0's entropy observer (Layer 4 data source)
  Conceptually belongs to the *validation substrate* beneath all five
  layers.

- **Proposal B — libtrust_wine_shim.** Sits at Layer 2 (PE runtime) as an
  alternative PE execution path that delegates compat to Wine while
  retaining kernel gate. Compositional — does not replace our pe-loader,
  *complements* it for non-security-sensitive binaries.

- **Proposal C — self-attestation quine (RF §3).** Sits at Layer 0 as an
  addition to the APE proof input — fold SHA-256(trust.ko .text) into
  every proof. Cross-cutting: also affects the self-attest loop
  visualised in §3.

- **Proposal D (from research-D §3.4) — TPM RNG mix into APE SEED.** Sits
  at Layer 0 in `trust_ape_create_entity`.

- **Proposal E (from research-I §4) — empirical bisimulation harness.**
  Sits beneath all layers as a cross-substrate validation tool;
  architectural position is "testing infra that straddles x86_64 kernel
  and RISC-V FPGA."

These 5 together form the **defensibility stack**: adversarial harness
proves theorems hold; wine-shim proves tier-1 moat is real; self-attest
proves moat integrity; TPM-SEED proves crypto posture; bisim proves
paper↔code correspondence. Together they close the "claimed but not
demonstrated" gap that currently dominates the moat story (RJ §3.3).

---

## §10. Parking lot — architectural items deferred to S75+

These are architecturally sound but explicitly out-of-scope for S74.
Listed with their research-report anchor so they are rediscoverable.

| Item | Research-report anchor | Why parked |
|------|------------------------|------------|
| Monte Carlo module for cortex | RA §2.6, §5 | Compound value across 4 existing features; ~350 LOC; not urgent for S74 stability |
| Analog amplitude rail (VN 1958 mixed precision) | RA §2.9 | Fixes 8.8 fp saturation; ~200 LOC; architectural but not S74-critical |
| VN mean ergodic witness | RA §2.4 | Quality-of-service metric; ~120 LOC |
| Empirical bisim harness | RI §4 | S75 top-3; ~680 LOC; requires QEMU RISC-V agent 4 from S74 to land first |
| Population census (library-keyed) | RH §1.1 | Autopoiesis criterion-1 gap; ~250 LOC |
| Ecosystem observer (Φ, MI) | RH §1.7 | IIT-lite for cortex; ~200 LOC |
| Reconfigurable-hash bring-back | RD §3.3 item 10 | Depends on Finding #10 triage |
| RISC-V port (full, not just QEMU phase 1) | `docs/riscv-portability-deltas.md` | Multi-session effort; S75+ |
| Sail spec for the 27-instruction ISA | RI §2.6 | 3-5 person-years if formal; even the empirical bisim needs a spec |
| Bennett logical-depth observer | RH §1.6 | ~110 LOC; important for ransomware discrimination |
| Differential observer (Bateson filter) | RH §1.4 | ~150 LOC; observers mostly publish levels not deltas |
| Self-model (meta_cortex) | RH §1.2 | ~280 LOC; partial Rosen closure |
| Hierarchical predictive coding (2-level) | RH §1.8 | ~300 LOC; cortex maturity |
| Histone modification marks (per-segment history) | RB §7 | ~250 LOC; cortex signal depth for per-segment patterns |
| Real meiotic crossover | RB §3, RE §4 | ~200 LOC; makes the 23-pair structure mechanically useful |
| Two-stage caspase cascade (rescuable apoptosis) | RB §9 | ~180 LOC; cortex rescue window |
| Adaptive immunity / threat spacer ring | RB §8 | ~300 LOC; biology-faithful + real security upgrade |
| PKRU / MKTME key-domain separation for APE | RD §1.4 | Hardware-dependent; defense-in-depth |
| Hibernation-image protection (`__nosave`) for APE state | RD §3.3 item 6 | Small but load-bearing |
| Cache-line flushing after APE memzero | RD §3.3 item 5 | `CLFLUSHOPT` addition |
| libtrust_wine_shim | RJ §5 B | S76-S77 — large; compositional but needs trust_lsm refactor first |
| Action lattice (Birkhoff-von Neumann quantum logic framing) | RA §2.2 | 0 LOC code, prose addition |
| CRISPR-style quorum metadata edit (not handler edit) | RF §5 | ~400 LOC; requires solid quorum first |
| Build-time homoiconicity via Scheme-macro codegen | RF §3 | ~120 LOC; build-quality-of-life |
| Fused-op self-test machine check | RF §2 | ~80 LOC; CI hardening |

---

## References — inter-document cross-reference

All 10 research reports are referenced above. Summary:

- **`docs/research/s74_a_vonneumann_beyond.md`** — less-cited Von Neumann;
  APE ≡ Process 1, Monte Carlo absent, mixed-precision missing
- **`docs/research/s74_b_biology_exact.md`** — mechanism-level biology
  fidelity audit; 12 mechanisms graded, 2 faithful / 5 partial / 3
  metaphor / 2 absent
- **`docs/research/s74_c_endosymbiosis.md`** — 14 mitochondrial-signaling
  mechanisms; cytochrome-c-release (algedonic) is priority-1 gap
- **`docs/research/s74_d_crypto_audit.md`** — 37-citation survey of hash
  chains / sigs / PRNG; APE novelty = behavioral-state binding
- **`docs/research/s74_e_chromosomal_model.md`** — 23-pair / XY / meiosis
  biology-vs-metaphor; meiosis 0/5 essential properties
- **`docs/research/s74_f_homoiconic_isa.md`** — reject homoiconicity,
  keep ISA stored-program + harden dispatch rodata
- **`docs/research/s74_g_reliability_consensus.md`** — quorum is CFT+,
  not BFT; kernel-write adversary breaks it
- **`docs/research/s74_h_observation_primitives.md`** — 8 frameworks →
  10 observation primitives; 5.5/10 coverage; algedonic reader is
  priority-1
- **`docs/research/s74_i_bisimulation.md`** — weak bisim + empirical
  harness = engineering-tolerable validation; formal proof 3-5
  person-years
- **`docs/research/s74_j_moat_landscape.md`** — 14 comparators; APE +
  chromosome + ISA are the defensible moat; biology overclaimed

Code-level evidence paths (all absolute on
`C:\Users\wilde\Downloads\arch-linux-with-full-ai-control\`):

- `trust/kernel/trust_dispatch.c:1293` — the mutable dispatch table
- `trust/kernel/trust_ape.c:454-568` — the APE construction
- `trust/kernel/trust_ape.h:71, 88` — the missing `consume_proof_v2`
  declaration
- `trust/kernel/trust_quorum.c:194-197` — the sysfs path
  (`/sys/kernel/quorum`)
- `trust/include/trust_quorum.h:48` — the sysfs path documented
  (`/sys/kernel/trust/quorum/*`)
- `trust/kernel/trust_algedonic.c:253` — the emitter
- `pe-loader/include/eventbus/pe_event.h:47` — `PE_EVT_EXCEPTION` declared
- `ai-control/cortex/active_inference.py` — S74 agent 6, references
  algedonic conceptually but no device reader
- `docs/architecture.md:§1-§6` — prior architecture spec, still correct
  on trust ontologies + event bus

---

**End of architecture-v2.md.**
