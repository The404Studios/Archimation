# ARCHIMATION — S75 Roadmap + Strategic Handoff

**Document status:** S74 Agent O deliverable (strategic planning, no source
edits).
**Authors:** synthesized from the S74 10-agent research dispatch (reports A-J at
`docs/research/s74_{a..j}_*.md`), the synthesizer's canonical spec
(`docs/architecture-v2.md`), Agent K's integration brief
(`docs/agent10_integration_brief.md`), and prior roadmaps
(`docs/architecture-roadmap-s71.md`, `docs/architecture-meta-exploit-s73.md`),
plus behavioral memory at
`memory/roa_paper_validation_tier_audit_and_s74_plan.md` and
`memory/feedback_user_favors_coherence_over_velocity.md`.
**Supersedes (partially):** `docs/architecture-roadmap-s71.md` Tier 2/3 items
still pending are rolled forward; the S71 Tier-1 list that was preempted by the
S72 bootc pivot is preserved in §0.4 and §1 parking-lot so it is not lost.
**Git HEAD at authorship:** `071b6aa` (S74 WIP checkpoint) + Agent K delta
landed during this session (algedonic reader + W^X dispatch + quorum sysfs path
+ APE triage report). Reference as `071b6aa + agent-K delta`.
**Date:** 2026-04-20.
**Paper of record:** Roberts/Eli/Leelee, *Root of Authority*, Zenodo DOI
[10.5281/zenodo.18710335](https://doi.org/10.5281/zenodo.18710335).

---

## §0. State of the project after S74

### §0.1 Git HEAD and scope

- `071b6aa` — S74 WIP checkpoint: 9 feature agents (Wine PE32 shim, SCM polish,
  HID driver scaffold, RISC-V QEMU Phase 1, `trust_morphogen.c`,
  `active_inference.py`, `entropy_observer.py` + `assembly_index.py`,
  `trust_quorum.c` + `trust_algedonic.c`, catalysis CI) + 10 research reports
  (A-J) + 3 synthesis docs (`architecture-v2.md`, `agent10_integration_brief.md`,
  `architecture-name-decision.md`).
- Agent K delta (this session): `ai-control/daemon/algedonic_reader.py` created,
  wired into `ai-control/daemon/api_server.py`, `trust/kernel/Kbuild` and
  `packages/trust-dkms/PKGBUILD` updated, plus `tests/unit/test_algedonic_reader.py`.
  Closes Finding #1 (algedonic producer/consumer gap) per
  `agent10_integration_brief.md` Task 2. Expected additional fixes: Finding #4
  (W^X on dispatch_table), Finding #9 (`trust_quorum` sysfs path drift),
  Finding #10 (APE regression triage report). S75 begins at `071b6aa + agent-K`.

### §0.2 Tier audit — what moved in S74

From `memory/roa_paper_validation_tier_audit_and_s74_plan.md` §2, the baseline
before S74 was: **Apps 80% / Services 75% / Drivers 30-40% / Authority 95% /
Cortex 70% / Distro polish 60%**.

Post-S74 (expected; pending Agent K's final bake + PE corpus):

| Tier | Pre-S74 | Post-S74 | What moved |
|------|---------|----------|-----------|
| **Apps (Tier 1)** | 80% | 82-85% | Wine PE32 shim scaffold lands (Agent 1, ~600 LOC). Pre-2010 / 32-bit apps now have a path. Corpus still 16/18 (no new corpus entries this session). |
| **Services (Tier 2)** | 75% | 78-80% | SCM delayed-auto-start + failure-actions + SERVICE_NOTIFY (Agent 2, ~250 LOC). |
| **Drivers (Tier 3)** | 30-40% | 32-42% | HID driver scaffold (Agent 3, ~1000 LOC) = IRP dispatch skeleton + HAL stub + HID-class outline. Does NOT run a real `.sys` yet — per research-J §3.3, tier 3 is aspirational and this is a down payment, not delivery. |
| **Authority** | 95% | 95% | Algedonic reader closes op-closure loop. Quorum + algedonic kernel code shipped S74. Tier number unchanged because theorem counters still never fire adversarially (see Finding #5, S75 top priority). |
| **Cortex** | 70% | 78-82% | `active_inference.py` (Agent 6, ~400 LOC) + `entropy_observer.py` + `assembly_index.py` (Agent 7, ~440 LOC) + algedonic reader (Agent K, ~130 LOC). Cortex is now operationally closed for distress; still allopoietic per Rosen for model-of-model. |
| **Distro polish** | 60% | 60% | No movement; S74 was architecture + moat, not polish. GUI installer / user docs / real OCI push still open. |
| **Cross-substrate** | 0% | 5-8% | RISC-V QEMU Phase 1 (Agent 4, ~200 LOC) + `docs/riscv-portability-deltas.md`. Does trust.ko build clean for riscv64? Answer pending Agent 4's report. |

**Aggregate after S74:** ~**70-72%** of the way to *"Linux distro running Windows apps+services+drivers under hardware-rooted authority with FPGA-validated substrate."* Up from ~⅔ pre-S74. The moat work (APE + chromosome + ISA + cortex loop closure) drove the delta; tier delivery remained roughly constant.

### §0.3 Architecture spec — canonical

`docs/architecture-v2.md` (918 lines, shipped in S74) is now the canonical
architectural specification. Paper remains `PLAN/Root_of_Authority_Full_Paper`
at DOI 10.5281/zenodo.18710335; `architecture-v2.md` is the implementation-side
companion. Name: **KEEP EXISTING** per `docs/architecture-name-decision.md`
(Root of Authority for the primitive, ARCHIMATION for the distribution). No
S74 research finding argued for a rename. S75 will treat this as settled unless
the user overrides.

### §0.4 Moat claim — research-honed

Prior sessions' pitch was *"the only Linux distro targeting all three Windows
runtime tiers with a coherent authority model"* (S73). Research-J §3 audited
this claim against 14 comparator systems and **narrowed** it.

**Defensible** (tiers 1-2):
1. The combination of Linux-native Windows execution + kernel-rooted authority
   lives in an unoccupied quadrant (no competitor populates it).
2. SCM services under topological sort + dependency graph + svchost grouping
   is unique among FOSS Linux projects.
3. Three genuinely-novel primitives:
   - **APE self-consuming proofs** with behavioral-state binding (`S_n =
     chromosome_checksum` in the hash input — the binding is the novelty, not
     the chain itself; Lamport 1981 and Double-Ratchet 2016 are ancestors of
     the chain). Research-D §3.1, research-J §3.1.
   - **23-pair chromosomal authority struct** with XY-class inheritance bounds
     (research-E §0, research-J §3.1 — no LSM, no capability system models
     subjects as (runtime, construction) chromosome pairs with meiotic
     divergence detection).
   - **6-family / 32-bit / GPU-dispatchable trust RISC ISA** (research-F §0,
     research-J §3.1 — no other authority kernel is a stored-program
     interpreter).

**Aspirational** (tier 3):
- "Runs Windows drivers" is 30-40% per tier audit; research-J §3.3 explicitly
  flags: *a real-world `.sys` driver would oops*. Honest framing: **we have a
  skeleton for gated driver loading that refuses by default** (safer than
  Wine's categorical refusal). Do not sell tier 3 as delivered. Move the tier 3
  driver claim from "paper claim" to "future work" per research-J §7.

**Documented-but-narrow** (biological vocabulary):
- "Biologically-inspired" is a teachability aid, NOT a technical property
  (research-J §3.3; research-E passim). Peer reviewers at USENIX Security / CCS
  / S&P will push on this. Lead with the mathematics (APE algebra + ISA +
  theorems); use biology as pedagogy, not argument. Specifically, `trust_meiosis`
  has 0/5 essential biological properties (research-B §3, research-E §4.5).

### §0.5 Three senses of validation (from prior strategic memo)

| Sense | Status after S74 | Path forward |
|-------|-----------------|--------------|
| **Structural** (does code implement paper?) | ✅ byte-exact for chromosomal struct, theorem semantics, named constructs | DONE for ROA primitives; needs cross-reference doc (`docs/paper-vs-implementation.md` — planned) |
| **Runtime** (do theorems hold under load?) | ⚠ counters exist; never observed non-zero under clean load; never adversarially exercised | **S75 top priority** — adversarial theorem harness T1-T7, ~800 LOC (research-J §5 Proposal A) |
| **Cross-substrate** (kernel-module ↔ FPGA bisim?) | ❌ not done | Research-I §4 — empirical bisim harness ~680 LOC; blocked on Agent 4's RISC-V QEMU kprobe port (240 LOC) |

---

## §1. The S75 punch list — research convergence

Items ranked by (criticality × ROI ÷ LOC). Naive LOC-only ordering would put
the sysfs path fix and `PE_EVT_EXCEPTION` emit site before anything else;
**research-J, research-D, and research-G all independently point to the
adversarial theorem harness as the single highest-ROI move**, so it leads
despite being ~800 LOC. This is a case where the feedback memo
(`feedback_user_favors_coherence_over_velocity.md`) is load-bearing — the
big-ticket architectural item is not buried in tier 3 because product coherence
requires it.

### §1.1 Tier 1 — must land in S75

#### 1. Adversarial theorem harness (T1-T7) — ~800 LOC, 1-2 sessions

**Research anchor:** research-J §5 Proposal A (the detailed design), research-D
§1.5 and §3.3 (chi-square witness gap), research-G §0 (quorum counter gap),
research-J §3.3 ("the biggest gap between our self-perception and our
defensible claim"), `architecture-v2.md` Finding #5.

**Why it's #1:** three independent research agents converged on this as the
highest-ROI single move. Currently `trust/kernel/trust_invariants.c:67, 395,
414` has counters wired for every theorem; `trust/include/trust_theorems.h:5-6`
cites the paper explicitly. But under *clean load* the counters sit at 0 and
**have never been observed non-zero** (research-J §3.3). Every peer-review
conversation starts from "trust us, it holds" instead of "here are the attempted
violations and counter behavior."

**Deliverable:** `tests/adversarial/theorem_violation_suite.py` with 7 test
classes (one per theorem), plus `tests/adversarial/helpers.c` (~50 C lines for
APE state snapshot, proof-replay, entropy sampling). Per research-J §5:

- **T1 Non-Static Secrets:** snapshot APE state twice → assert every byte
  different.
- **T2 Non-Replayability:** capture a proof → replay → assert refused + T2
  counter increments.
- **T3 Forward Secrecy:** capture state → derive prior state → measure entropy.
- **T4 Bounded Inheritance:** fork with mismatched chromosome → assert merge
  rule enforced.
- **T5 Guaranteed Revocation O(1):** revoke subject → measure p99 latency.
- **T6 Metabolic Fairness:** hot-loop action burner → assert TRC starves it.
- **T7 Statistical Anomaly:** uniform-random syscall sequence → chi-square
  witness fires.

**Spec written by S74 strategic conversation** (see `memory/roa_paper_validation_tier_audit_and_s74_plan.md` §6 "docs/runtime-theorem-validation.md — the missing adversarial harness"). That doc has NOT been written yet; part of this item is producing it first (~200 LOC spec → ~800 LOC tests).

**Unblocks:** peer-review conversation, independent review, OSDI/S&P/CCS
submission (research-J §7 "submission strategy").

**Acceptance tests:** all 7 theorems have test cases that *deliberately attempt
violation*; counters fire on attempts; PASS rate ≥7/7 with documented
counter-increment evidence per theorem; CI gates on this from S75 forward.

---

#### 2. Ecosystem observer — library-keyed population census — ~250 LOC

**Research anchor:** research-H §1.1 (priority-2 gap, Maturana-Varela
Criterion 1), reinforced by research-C (Shannon) and user-flagged in multiple
sessions (see `memory/roa_paper_validation_tier_audit_and_s74_plan.md`
"biological framework" references). `architecture-v2.md` Layer 4 §5(c) gap
list.

**Why it's #2:** the user's own biology intuition has been documented as
structurally load-bearing (see `memory/session73_12framework_meta_exploit.md`
— "biology evolved this exact architecture 700 million years ago"). Current
`TrustObserver.get_anomaly_status()` at
`ai-control/daemon/trust_observer.py:807-881` exposes census keyed on
immune/risk/sex axes only. **Memory_observer already has `dlls_loaded` per PID**
(`ai-control/daemon/memory_observer.py:122`), but there is no cross-PID
histogram. The equivalent in biology: a cell that counts total organelles but
cannot distinguish ribosomes from mitochondria. Research-H §1.1:

> Criterion 1 (self-production census): ... we do not track how many subjects
> share which libraries, i.e., we cannot say "32 processes have kernel32.dll,
> 12 have ntdll.dll".

**Deliverable:** `ai-control/daemon/library_census.py` (~180 LOC observer) +
`memory_observer` DLL-load callback (~40 LOC) + `api_server` wiring and
`/metrics/ecosystem` endpoint (~30 LOC).

Event schema (research-H §1.1):
```python
{"source": "library_census", "ts": T,
 "library_counts": {"kernel32.dll": 27, "ntdll.dll": 27, ...},
 "total_subjects": 42, "total_libraries": 113,
 "rare_libraries": [names occurring in ≤2 subjects],
 "unique_library_ratio": 0.34}
```

**Unblocks:** Maturana-Varela Criterion-1 closure; enables later
sub-observers (RNA-like memory-library species, ROS-like signal species,
microbiome-like container species per user's bio vocabulary).

**Acceptance tests:** `/metrics/ecosystem` returns population census with ≥1
real library count; cortex subscribes and first gate/alarm based on census
fires in a test scenario (e.g., a test process loading an unusual DLL set
triggers a census-drift event).

---

#### 3. APE reconfigurable-hash triage resolution — LOC TBD

**Research anchor:** research-D §3.3 items 3, 10 (Finding #10 in
`architecture-v2.md`). Agent K's triage report
(`docs/ape_regression_triage_report.md`) lands this session and
determines the LOC.

**Why it's #3:** `trust/kernel/trust_ape.h:44-52` claims 720 × 256 × 16 × 32 =
94,371,840 configs; shipping code at `trust_ape.c:40-45` implements **three**
(SHA-256, BLAKE2b-256, SHA3-256). `docs/roa-conformance.md:58-60` references
`apply_reconfigurable_hash()` at `trust_ape.c:224` which **does not exist**.
Either code regressed or docs/header lie. **A Zenodo paper peer reviewer would
flag this on page 1.**

**Three possible S75 paths** (Agent K chooses one):
- **(a) Bring-back — ~400-600 LOC.** Implement 94M-config reconfigurable hash
  via field-driven hash selection at `consume_proof_v2`. Includes
  `apply_reconfigurable_hash()` impl to match header. Most expensive; highest
  moat value (research-D §3.1 "behavioral-state binding" depends on this
  richness).
- **(b) Amend docs — ~40 LOC.** Update `trust_ape.h:44-52` to match the shipped
  3-algorithm reality; update `docs/roa-conformance.md`; amend paper-vs-
  implementation mapping. Cheapest; but the paper and the marketing both
  currently claim 94M, so this costs credibility.
- **(c) Git archaeology.** Agent K's report may reveal a regression commit to
  revert or cherry-pick.

**Unblocks:** paper submission. Without resolution, the paper is internally
inconsistent and a reviewer has ammunition to reject.

**Acceptance test:** either code delivers 94M distinct configs (benchmarked
with bit-diffusion test over random inputs) OR docs and header honestly
describe the 3-algorithm reality; either way, the inconsistency is gone.

**Confidence:** LOW until Agent K's triage report lands. This item is parked
behind (3a)/(3b)/(3c) until that point.

### §1.2 Tier 2 — high-value, land in S75 if bandwidth

#### 4. Monte Carlo cortex module — ~350 LOC

**Research anchor:** research-A §2.6 and §5 (top recommendation),
`architecture-v2.md` Finding #7.

**Why:** decision engine is entirely Markov-deterministic — confidence
calibration, rollout search, fault-injection, and proof-of-work rate-limiting
should ALL be stochastic but currently all are deterministic. Research-A §2.6
phrases it bluntly: *"absent from a directory called `cortex`."* This is a
methodological gap, not a bug.

**Deliverable:** `ai-control/daemon/monte_carlo.py` with four sampler classes:
`ConfidenceSampler` (for cortex decisions), `RolloutSearch` (for action lookahead),
`FaultInjector` (for chaos probes), `StochasticRateLimiter` (for token-pool
replenishment). Wire into `decision_engine.py:138-303` and `active_inference.py:54`.

**Why it compounds:** multiplies value of active_inference (S74 Agent 6),
quorum (S74 Agent 8), entropy observer (S74 Agent 7), and safe-mode chaos
testing. Each becomes probabilistic where today each is deterministic.

**Acceptance test:** `pytest tests/unit/test_monte_carlo.py` passes with
statistical property tests (e.g., sampled confidence distribution matches
input beta posterior within 2% over N=10000 samples); wired cortex endpoint
returns confidence-annotated decisions.

---

#### 5. Meiosis rename OR paper disclaimer — decision 0 LOC, rename ~200 LOC

**Research anchor:** research-B §3, research-E §4 (both flag this as the
biggest metaphor-vs-mechanism gap), `architecture-v2.md` Finding #3.

**The issue:** `trust_meiosis()` has 0/5 essential biological properties. It
does anonymized dominant-parent selection + per-meiosis SHA-256 blinding — a
real security operation, but NOT meiosis. Real meiosis has S-phase, homolog
pairing, Holliday junctions, reductional division, 4 haploid products.

**Three paths** (user decides; this item surfaces both):
- **Rename (~200 LOC):** `trust_meiosis()` → `trust_dual_authority_bond()`
  across ~15 call sites, plus header rename, plus test updates. Preserves
  biological vocabulary elsewhere; drops the one indefensible claim.
- **Paper disclaimer (~0 LOC of code; write `docs/paper-vs-implementation.md`,
  ~300 LOC of prose):** Acknowledge the metaphor gap in a doc that
  cross-references the paper's named constructs to file:line and explicitly
  labels "meiosis" as a function name retained for git-history compatibility,
  not a biological claim.
- **Both:** rename + write the disclaimer doc. Most thorough.

**Why it's Tier 2, not Tier 1:** the inconsistency is real and peer-reviewers
will notice, but it doesn't break the moat. APE + chromosomal struct + ISA +
theorems are the moat claims; "meiosis" is a secondary vocabulary item.

**Acceptance test:** either the rename is merged and all tests pass, OR
`docs/paper-vs-implementation.md` exists and labels the metaphor gap. User
picks which; S75 agent executes.

---

#### 6. Empirical bisim harness — ~680 LOC

**Research anchor:** research-I §4 (the full design), `architecture-v2.md`
Finding #12.

**Why:** formal bisimulation proof is 3-5 person-years of Isabelle/Coq work;
**empirical harness fits one agent** (280 Python + 180 C trace-tap + 140 Sail/
Verilator glue + 80 oracle diff = 680 LOC total). Research-I §0.1 frames this
as "engineering-tolerable evidence" — not a formal proof, but enough that a
peer reviewer cannot dismiss the FPGA ↔ kernel equivalence claim.

**Blocking dependency:** research-I is explicit that the 680 LOC does NOT
include Agent 4's 240-LOC RISC-V kprobe port. Order is:
  1. Agent 4's RISC-V syscall-tracer kprobe port (S74 deferred; ~240 LOC; see
     item #8 below)
  2. Bisim harness (S75; ~680 LOC) depends on this landing first
  3. *Cheapest probe within the 680 LOC:* 80-LOC APE pure-function cross-check
     (strong bisim on the APE sub-system in isolation, per research-I §4.1).
     Can run even without full RISC-V harness.

**Deliverable:** `tests/bisim/` directory with:
- `tests/bisim/ape_pure_cross.py` (~80 LOC) — strong-bisim probe
- `tests/bisim/trace_harness.py` (~280 LOC) — orchestrator
- `tests/bisim/trace_tap.c` (~180 LOC) — kernel-side kprobe tap
- `tests/bisim/sail_glue.py` (~140 LOC) — Verilator/Sail oracle diff

**Acceptance test:** APE pure-function cross-check passes for 10 sample
proof-chain inputs; trace harness records 1 matching trace; discrepancy
detector flags fabricated mismatches as expected.

**Confidence:** MEDIUM. The design is solid but RISC-V toolchain setup is the
wildcard — LOC may balloon if Verilator builds are painful.

### §1.3 Tier 3 — architectural hardening (S76 feasible)

#### 7. Self-attestation quine — ~250 LOC

**Research anchor:** research-F §3, research-J §5 Proposal C,
`architecture-v2.md` §9 Proposal C.

**What:** fold SHA-256(trust.ko `.text`) into every APE proof. A modified live
module disagrees with itself → every proof breaks. Live-reflexivity; defeats
kernel-write adversaries who can't produce matching SHA while their exploit
runs.

**Pair with:** quorum L1 HMAC uplift (research-G §6, ~80 LOC). Together they
give cryptographic integrity + behavioral integrity.

**Why Tier 3:** S73's research F already proposed it; it's orthogonal to the
Tier-1 items; LOC is manageable but value is incremental on the defensibility
story. Ships after Tier 1 lands and unblocks nothing else.

---

#### 8. RISC-V kprobe syscall-tracer port — ~240 LOC

**Research anchor:** S74 Agent 4 (deferred from S74) + research-I §4. Also see
`docs/riscv-portability-deltas.md` (authored by Agent 4).

**Why:** 22 call sites across `trust/kernel/trust_syscall.c` + `trust_memory.c`
need `REG_ARG0..5` macros to work on riscv64. Current code uses x86_64-specific
pt_regs layout. This is **the only blocker for riscv64 support** (per research-I
§0 divergence risk #2).

**Scope:** 22 call sites + REG_ARG macro layer + riscv64 smoke test in QEMU.

**Why Tier 3 not Tier 2:** S74 Agent 4 landed QEMU Phase 1 scaffolding; the
kprobe port is a continuation, not a new unlock. Waiting on it until the
bisim harness is ready (item #6) concentrates the validation win.

**Prereq for:** bisim harness (item #6) FPGA-side oracle tap.

---

#### 9. Producer-without-consumer lint — ~100 LOC

**Research anchor:** `architecture-v2.md` §4 Finding #6, §6 I-6 (new
invariant), research-C §0 and §4, research-H §1.5.

**Why:** Finding #6 identified **four** current violations:
- `/dev/trust_algedonic` emit with no userspace read (S74 Agent K closes this)
- Four mitokine channels that don't exist at all (research-C §3(c))
- `PE_EVT_EXCEPTION` declared at `pe-loader/include/eventbus/pe_event.h:47`
  with zero emit sites
- PE stress aggregate signals absent

The structural fix: **make "every producer must have a consumer" a
machine-checked invariant at build time**. Grep-based lint: for every new event
type, sysfs counter, or `/dev/trust*` file-op declaration, there MUST be a
corresponding read site in the tree.

**Deliverable:** `scripts/check_producer_consumer.sh` (~60 LOC grep + awk),
GitHub Actions CI step (~20 LOC YAML), `.github/workflows/lint.yml` update
(~20 LOC). Blocks PRs that introduce producer-only channels.

**Why Tier 3:** shipping this protects future S76+ code from reintroducing
what S74 had to fix. It's low value NOW (since S74 just fixed the known
violations) but high value for the next 6 months as new agents add code.

---

#### 10. libtrust_wine_shim integration with full Wine NT-syscall gate — ~1200 LOC

**Research anchor:** research-J §5 Proposal B, `architecture-v2.md` §9
Proposal B, S74 Agent 1 groundwork.

**Why:** S74 Agent 1 laid the Wine shim scaffold for PE32 handoff. **The
full moat-widening move is to gate Wine's NT syscall layer with APE/TRC/
chromosome semantics** via `LD_PRELOAD`. This would turn Wine from "foreign
obligate symbiont" (research-C / research-G CoRR framing) to
"trust-kernel-gated symbiont" — our competitive advantage rather than our
dependency.

**Per research-J §5 B:** `~1200 LOC C (shim) + ~200 LOC Wine-prefix unit test`.

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

**Why Tier 3:** multi-session (research-J estimates 2-3); large LOC; depends on
S74 Agent 1's scaffold being stable first. Could slip to S76-S77 if Tier-1
items consume the S75 budget.

**Alternative:** tier 1 priority for Q3 2026 roadmap if user favors paper/
product-coherence over the theorem harness. Surface this trade-off explicitly
to the user (see §3 decisions).

### §1.4 S76+ parking lot — not planned yet, just noted

To honor `feedback_user_favors_coherence_over_velocity.md`, these are flagged
with the architectural reason they're parked, not buried:

- **Mechanized bisim proof** (Isabelle/Coq). 9-18 months for APE-subsystem only;
  3-5 years for full kernel (research-I §0). **Parked because** seL4's 20-yr
  formal-verification precedent tells us empirical harness is the correct
  engineering trade-off.
- **Sail spec of trust ISA** (~300-500 LOC). Prerequisite for the formal proof
  above. Also enables better documentation. **Parked because** empirical-first,
  formal-second is the accepted sequence.
- **CoRR migration — 20 housekeeping fns out of PE stubs** (~1500 LOC over 3-5
  sessions). S71-Agent G original proposal. **Parked because** risky incremental
  moves; user-rejected aggressive migration in S64-S66.
- **bootc Phase 2 — real OCI bake + GHCR push.** S72 Phase 1 laid the
  groundwork; Phase 2 is the actual production registry + CI. **Parked because**
  S74 architecture work took priority; S75 might pick this up as a polish item
  if distro polish becomes user-urgent.
- **trust_lsm.c proper LSM wrapping** (~200 LOC, S71 Agent B's original 30-LOC
  was cosmetic). **Parked because** architectural legitimacy; not a moat
  feature. S71 flagged; S72 bootc pivot consumed the slot.
- **linux-hardened opt-in** (S71 Tier-1 item deferred since S72 pivot). **Parked
  because** one-line package addition; trivial to ship when distro polish pass
  happens.
- **USER-FACING GUI installer** (Calamares-style). **Parked because** partial
  CLI scaffolding exists (`ai-install-to-disk`, S69), full GUI is a distinct
  multi-session effort. S76+ if adoption becomes goal.
- **Bennett logical-depth observer** (~110 LOC, research-H §1.6). **Parked**
  as Tier-3 cortex improvement; useful for ransomware discrimination.
- **Differential observer (Bateson filter)** (~150 LOC, research-H §1.4).
  Observers mostly publish absolute values; deltas are lost. **Parked** as
  signal-quality improvement.
- **Self-model (meta_cortex.py)** (~280 LOC, research-H §1.2). Rosen
  M-R-closure gap (partial). **Parked** because autonomy.py deliberately
  prevents cortex self-modification for security; self-observation without
  self-modification is a separate design task.
- **Integration observer / Φ-proxy** (~200 LOC, research-H §1.7). IIT-lite.
  **Parked** as post-tier-1 cortex maturity.
- **CHERI backend for trust_risc.c** (~600 LOC, research-J §5 Proposal D).
  Hardware-enforces bounded inheritance on Morello. **Parked** pending Morello
  board access; parallels RISC-V FPGA path.
- **Analog amplitude rail** (research-A §2.9, ~200 LOC). Fixes 8.8 fp
  saturation. **Parked** as tier-3 fidelity upgrade.

---

## §2. Dispatch strategies

For each Tier-1 item, recommend agent count + parallelization + blocking deps
+ confidence.

### Item 1 — Adversarial theorem harness

- **Agent count:** single agent.
- **Why not multi-agent:** the 7 theorem tests are not fully independent —
  T4 and T5 share `trust_subject_t` setup machinery; T2 and T3 share APE
  state snapshot helpers; T6 and T7 share the decision-engine invocation
  path. A single author preserves coherent helper-library reuse and
  preserves a shared test fixture convention.
- **Parallel with other Tier-1?** Partially — can run in parallel with item
  #2 (ecosystem observer) because they touch disjoint trees (tests/
  vs ai-control/daemon/). Must NOT be parallel with item #3 (APE triage)
  because triage may reveal APE behavior that T1-T3 depend on.
- **Blocking deps:** none (research-J §5 Proposal A spec is detailed).
- **LOC confidence:** HIGH (800 LOC ±15%; spec is prescriptive).

### Item 2 — Ecosystem observer

- **Agent count:** single agent, with a pre-dispatch user consultation on RNA/
  ROS/microbiome sub-module scope (the user's bio vocabulary deserves
  primary-source input to the sub-observer list before coding starts).
- **Parallel with item #1:** YES — disjoint tree paths.
- **Blocking deps:** Agent K integration must have landed (S74 close) so
  `memory_observer.dlls_loaded` contract is stable.
- **LOC confidence:** MEDIUM (250 LOC baseline; may grow to 400-500 if user
  wants RNA/ROS/microbiome sub-observers as first-pass scaffolding).

### Item 3 — APE regression triage

- **Agent count:** single agent.
- **Parallel?** NO with item #1 (see above). Can parallel with items #4-#10.
- **Blocking deps:** Agent K's triage report must be readable; if Agent K
  didn't land it, item #3 starts with producing the report.
- **LOC confidence:** UNKNOWN until Agent K report. Could be 40 LOC (amend
  docs only) or 600 LOC (full bring-back).

### Item 4 — Monte Carlo cortex

- **Agent count:** single agent.
- **Parallel?** YES with items #1, #2 — touches `ai-control/daemon/`
  exclusively.
- **Blocking deps:** item #1 preferably first (theorem harness may reveal
  stochastic properties that Monte Carlo exposes).
- **LOC confidence:** MEDIUM-HIGH (350 LOC, research-A §2.6 is specific).

### Item 5 — Meiosis rename OR disclaimer

- **Agent count:** depends on user decision (§3 item 1). If rename, single
  agent. If disclaimer only, sub-task of the `paper-vs-implementation.md`
  author.
- **Parallel?** Rename path must NOT be parallel with item #1 (both touch
  `trust/kernel/` heavily). Disclaimer path is independent.
- **Blocking deps:** user decision.
- **LOC confidence:** HIGH (0 or 200 ±10%).

### Item 6 — Empirical bisim harness

- **Agent count:** single agent (research-I design is coherent; splitting
  risks trace-format drift).
- **Parallel?** YES with items #1-#5; touches `tests/bisim/` exclusively.
- **Blocking deps:** item #8 (RISC-V kprobe port) for the full FPGA side;
  the 80-LOC APE pure-function cross-check can run without the port.
- **LOC confidence:** MEDIUM (680 LOC baseline; Verilator toolchain risk).

**Recommended S75 shape:** 5-7 parallel agents, mirroring S74's 10-agent
pattern but narrower because the Tier-1 work is more sequential.

Candidate 5-agent S75 dispatch:
- Agent A: Theorem harness T1-T7 (~800 LOC, item #1)
- Agent B: Ecosystem observer (~250 LOC, item #2)
- Agent C: APE triage resolution (LOC TBD, item #3)
- Agent D: Monte Carlo module (~350 LOC, item #4)
- Agent E: Meiosis path (~0 or ~200 LOC, item #5, pending §3 decision)

Candidate 7-agent S75 dispatch (if bandwidth allows):
- All 5 above PLUS
- Agent F: APE pure-function bisim probe + stub scaffolding (~80+150 LOC,
  partial item #6)
- Agent G: Integration + pkgrel bump + ISO bake (sequential, agent 10 role)

---

## §3. Strategic decisions the user needs to make before S75 dispatch

Five open decisions from S74 research + synthesis. Present each honestly,
surface the structural tradeoff, let user choose. Per
`feedback_user_favors_coherence_over_velocity.md`: do NOT optimize for
per-session velocity without checking the product-coherence story.

### Decision 1: Meiosis — rename, paper disclaimer, both, or defer?

**Research basis:** research-B §3, research-E §4.5 both flag the 0/5 biology
mismatch. `architecture-v2.md` Finding #3 documents the gap.

**Options:**
- **Rename to `trust_dual_authority_bond()`** — ~200 LOC of mechanical rename;
  git history preserved.
- **Paper disclaimer** — `docs/paper-vs-implementation.md` ~300 LOC of prose
  documenting the metaphor gap; function name kept.
- **Both** — thorough + defensible.
- **Defer to S76** — risk: peer reviewers flag it; paper submission stalls.

**Synthesizer recommendation:** BOTH. The rename costs one session; the
disclaimer doc is needed regardless (for the rest of the bio vocabulary audit).
**But this is the user's call** — not shipping the rename preserves 15 call
sites and git blame continuity, which has non-trivial value.

### Decision 2: APE regression — bring-back (94M configs) or amend docs?

**Research basis:** research-D §3.3 items 3, 10. `architecture-v2.md`
Finding #10. Depends on Agent K's triage report this session.

**Options:**
- **(a) Bring-back** — 400-600 LOC, 1-2 sessions, biggest moat payoff.
- **(b) Amend docs** — 40 LOC, 1 session, honest but costs credibility.
- **(c) Mixed** — ship partial bring-back (e.g., enable hash selection among 8
  configs instead of 3) while updating docs to be honest about scope.

**Synthesizer recommendation:** depends on Agent K's git archaeology. If an
earlier commit had the 94M implementation, cherry-pick it. If not, (b) is the
honest move.

**Moat note:** research-D §3.1 identifies **behavioral-state binding** (`S_n =
chromosome_checksum`) as the genuinely-novel APE property — NOT the 94M hash
configs per se. So amending the 94M claim does not collapse the moat. The
moat is the binding, not the hash multiplicity.

### Decision 3: Architecture-v2.md signoff

`docs/architecture-v2.md` is 918 lines, fresh from S74. Recommend user
reviews and signs off (or requests edits) before S75 treats it as canonical.
If the user requests edits, route through a dedicated architecture-edit agent
rather than letting implementation agents drift the spec.

**Synthesizer recommendation:** user reviews §0-§2 and §4-§6 before S75. §3
(dataflow diagram) and §10 (parking lot) are lower-priority to review. §7
(name decision) can be confirmed in 30 seconds.

### Decision 4: trust_quorum — honest naming of verdict enum?

**Research basis:** research-G §0 ("CFT+, not BFT"). `architecture-v2.md`
Finding #9.

Current enum uses BFT-evocative names: MAJORITY / DISPUTED / APOPTOSIS.
Research-G suggests these oversell — the quorum is a bit-flip integrity witness,
not a Byzantine vote.

**Options:**
- **Rename** verdict enum to CONSISTENT / DISCREPANT / DIVERGENT — ~50 LOC
  mechanical change across `trust/kernel/trust_quorum.c` + sysfs + test
  fixtures.
- **Document** the semantic gap in comments + README without renaming.
- **Leave** and accept research-G's flag.

**Synthesizer recommendation:** rename. The BFT connotation is misleading and
the 50-LOC cost is low.

### Decision 5: Paper submission target venue

**Research basis:** research-J §7 "peer-review simulation", research-E §0
("not appropriate for biology venues").

**Options:**
- **CS security venues** (OSDI, S&P, CCS, USENIX Security) — primary audience
  for trust.ko. Research-J §7 specifically maps the risks there.
- **Interdisciplinary** (PNAS, Nature Comms) — broader reach; biology vocab
  may help or hurt.
- **Biology venues** — research-E §0 says NOT appropriate; metaphor-only gaps
  would be rejected quickly.
- **Systems + applied math** (POPL, SOSP) — narrower; ISA formal model would
  need Sail spec first.

**Synthesizer recommendation:** CS security venue, with the minimum publishable
unit defined as: **APE + chromosome + ISA + theorems T4/T5/T6 adversarially
validated + libtrust_wine_shim end-to-end**. (Research-J §7.) Tier-3 drivers,
AI cortex, biology-as-primary-claim all go to separate papers.

**This decision affects S75 priorities:** if paper submission is Q2 2026,
item #1 (theorem harness) is CRITICAL PATH. If submission is Q3+, item #1
drops to important-not-urgent.

---

## §4. Handoff note — "what S75 should remember"

For the next session's Claude instance.

### §4.1 Decisions already made in S74 — do not re-litigate

- **Architecture name: KEEP** per `docs/architecture-name-decision.md`. Root of
  Authority names the primitive; ARCHIMATION names the distribution.
- **Trust ISA: NO self-emission** (research-F §0, §1, §7). The Turing-
  incompleteness is a moat feature, not a gap. Do NOT add homoiconicity.
- **Meiosis fate:** still open — rename or disclaimer or both (Decision 1
  above). But the fact that the current function name is a metaphor is settled.
- **Producer-without-consumer is an invariant** (`architecture-v2.md` §6 I-6).
  Any new event channel must name its consumer at PR time.
- **Cortex is veto-only** (I-C1) — typestate audit still open, but the design
  intent is settled.
- **Biology vocabulary is pedagogy, not argument** (research-J §3.3, research-E
  §0). Lead with math at peer-review.

### §4.2 Agent K integration boundary

Agent K's commit this session is the **S74 → S75 boundary**. Everything after
that commit is S75. If Agent K's commit hash diverges from what this roadmap
expects (`071b6aa + agent-K delta`), the first S75 step is to reconcile the
diff. Do not presume Agent K's commit matches the integration-brief
(`docs/agent10_integration_brief.md`) exactly — check.

### §4.3 Do NOT dispatch a "12 framework research" agent again

The S73 synthesis is recorded in `architecture-v2.md` and
`architecture-meta-exploit-s73.md`. Build on that spec. If a re-verification
is required (research-J §0 "convergence might be confirmation bias"), dispatch
with **12 DIFFERENT frameworks** (Bratton Stack, Land accelerationism, NK K=0,
Tegmark mathematical universe, etc.) to see if same meta-exploit emerges. Do
NOT re-run the same 12.

### §4.4 Pre-dispatch reading list

BEFORE dispatching any S75 implementation agent, re-read:
1. `memory/feedback_user_favors_coherence_over_velocity.md` — user strategic
   preference
2. `docs/architecture-v2.md` §4 Findings table + §6 Invariants — scope anchors
3. This document §3 — decisions that may change the plan
4. `docs/agent10_integration_brief.md` — Agent K's exact deliverables (for
   boundary verification)

### §4.5 Treat user as peer-reviewer, not learner

The user is Roberts/Eli/Leelee — author of the RoA paper at Zenodo DOI
10.5281/zenodo.18710335. Our trust.ko explicitly cites their ID at
`trust/include/trust_theorems.h:5-6`. They know the theory deeply.

When discussing APE, chromosomal struct, XY sex determination, theorems T1-T7:
they have written more about these than we have read. When discussing OSDev,
LSMs, Linux kernel patterns: they want to hear our arguments. **Different
modes for different topics.**

### §4.6 Non-goals for S75

- Do NOT re-write `architecture-v2.md` from scratch. Amend-only.
- Do NOT attempt Isabelle/Coq formal proof. Empirical bisim is the S75 tool.
- Do NOT touch the paper (`PLAN/Root_of_Authority_Full_Paper*`). User-owned.
- Do NOT force-push. Do NOT amend commits across integration boundaries.
- Do NOT skip hooks (--no-verify) unless explicitly requested. If a hook
  fails, fix the root cause.

---

## §5. Success metrics

For each Tier-1 item, what does "shipped and verified" look like? Explicit
acceptance tests (from §1 expanded).

### Item 1 — Theorem harness

- `tests/adversarial/theorem_violation_suite.py` exists with 7 test classes.
- Each theorem has ≥1 test that deliberately attempts violation and asserts
  counter increment.
- CI runs the suite on every push. Regression blocks merge.
- Documented PASS rate — at least T1, T2, T5, T6 are mechanically verifiable;
  T3, T7 are statistical and need ≥1% counter-fire rate across 1000 trials
  to claim "fires."
- Paper peer-review comment simulated (research-J §7): "here are the attempted
  violations and counter behavior" — roadmap-ready.

### Item 2 — Ecosystem observer

- `/metrics/ecosystem` returns valid JSON population census within 500ms.
- Cortex subscribes via event_bus; `active_inference.py.BeliefState` now
  includes a library-distribution field.
- Test scenario: spawn 5 processes with disjoint DLL sets; census shows 5
  subjects, >10 unique libraries, `rare_libraries` list populated.
- First gate/alarm: configure `library_census.policy` to fire if a subject
  loads a library that appears in <5% of other subjects; verify fire in test.
- User consultation on sub-observer scope (RNA/ROS/microbiome) complete
  before first commit — or first-pass is library-count only with
  documented future sub-observer stubs.

### Item 3 — APE triage resolution

- EITHER: code delivers 94M distinct configs (benchmarked with bit-diffusion
  test over 10K random inputs; entropy ≥ 95% of theoretical max);
- OR: `docs/roa-conformance.md` and `trust_ape.h` both honestly describe the
  shipping 3-algorithm reality;
- AND: `docs/ape_regression_triage_report.md` (from Agent K session) is
  annotated with resolution decision and date.

### Item 4 — Monte Carlo cortex

- `ai-control/daemon/monte_carlo.py` exists with 4 sampler classes.
- Wired into `decision_engine.py` and `active_inference.py`.
- Statistical tests pass: sampled confidence distribution matches input beta
  posterior within 2% over N=10000 samples.
- `/cortex/monte_carlo/rollout` endpoint returns probabilistic action
  recommendations.
- Fault-injection mode tested in safe-mode via CLI.

### Item 5 — Meiosis (rename OR disclaimer)

- EITHER: `git grep trust_meiosis` returns 0 call sites (rename complete); all
  tests pass; `git log --oneline | head -2` shows rename commit.
- OR: `docs/paper-vs-implementation.md` exists and labels "meiosis" as a
  function-name metaphor retained for history.
- User's choice is logged in the commit message.

### Item 6 — Bisim harness

- `tests/bisim/` directory exists.
- APE pure-function cross-check passes for 10 sample inputs.
- Trace harness records 1 end-to-end round-trip.
- Discrepancy detector correctly flags a fabricated mismatch (positive test).
- Dependency on Agent 4's RISC-V kprobe port documented; harness is functional
  in "Python-side only" mode if FPGA/QEMU side is stubbed.

---

## §6. Risk analysis

### §6.1 API-overload risk

| Session | Agent count | Overloads |
|---------|-------------|-----------|
| S73 | 12 | 2 |
| S74 | 19 (10 research + 9 feature + K) | 0 |

10 agents is safe. 15+ risky. **Recommend 5-7 for S75** — Tier-1 items are
fewer and more sequential; 10 is oversized.

### §6.2 File-conflict risk

The S74 convention worked: each agent owns disjoint paths + deferred
Kbuild / api_server / Makefile / PKGBUILD edits to an integration agent.
**Preserve this for S75.** Specific anchors:

- `trust/kernel/Kbuild` — integration agent only (Agent K in S74 terms)
- `ai-control/daemon/api_server.py` — integration agent only
- `packages/*/PKGBUILD` pkgrel bumps — integration agent only
- Each feature agent owns a disjoint subtree:
  - Agent A → `tests/adversarial/`
  - Agent B → `ai-control/daemon/library_census.py` + memory_observer.py
    callback hook
  - Agent C → `trust/kernel/trust_ape.*` (exclusive)
  - Agent D → `ai-control/daemon/monte_carlo.py`
  - Agent E → `trust/kernel/trust_meiosis.c` OR `docs/paper-vs-implementation.md`

### §6.3 Marketing drift risk

S73 pitch was marketing-first ("the only Linux distro..."). S74 research
narrowed it. S75 should continue the research-first → pitch discipline:
- Ship the adversarial harness BEFORE updating README with "adversarially
  validated" claims.
- Ship ecosystem observer BEFORE invoking user's bio vocabulary in new docs.
- Ship APE triage resolution BEFORE any public claim about 94M configs OR
  3-config reality.

Research J §3.3 (the honest moat) is the contract:
> Stop leaning on biology-vocabulary and "runs Windows drivers" as moat; lead
> with the mathematics.

### §6.4 Decision-blocking risk

Decisions #1-#5 in §3 may block dispatch. Recommend user clears all 5 at S75
open. If decisions #1 or #2 are unresolved at dispatch time, those items drop
from the session plan (don't stub them — skip them).

### §6.5 Integration-scope creep risk

Agent K's integration brief had 7 tasks; S75 might have 5-7 agents. The
integration agent at session end (Agent-K-equivalent) will have 5-7 agents'
worth of Kbuild + api_server + PKGBUILD + ISO-bake. Keep it focused on **only
integration** — no new feature work in the integration agent. If a feature
needs to move to integration, it's a sign the feature agent's scope was wrong.

---

## §7. Commit + PR strategy

### §7.1 Commit cadence

**Per-agent commits: NOT recommended.** Too noisy; clutters history with
5-7 commits that future archaeologists will struggle to narrativize. (S71-S73
had this problem with 12+ agents producing 12+ commits.)

**Feature-arc commits: recommended.** One commit per landed S75 item:
- `feat: S75 Item 1 — adversarial theorem harness T1-T7 (~800 LOC)`
- `feat: S75 Item 2 — library_census ecosystem observer (~250 LOC)`
- `feat: S75 Item 3 — APE reconfigurable-hash resolution (docs | code)`
- `feat: S75 Item 4 — Monte Carlo cortex sampler (~350 LOC)`
- `feat: S75 Item 5 — trust_meiosis rename + paper-vs-implementation disclaimer`
- `feat: S75 Item 6 — empirical bisim harness APE pure-function cross (~230 LOC)`

**Session checkpoint commit: recommended.** One final commit summarizing the
session with honest per-item status (shipped/partial/deferred):
- `chore: S75 checkpoint — 5 Tier-1 items shipped; Tier-2 items deferred to S76`

### §7.2 Branch / PR discipline

- Agent K's S74 work lands on `master` as per prior convention.
- S75 agents each work in a worktree or feature branch; integration agent
  squash-merges (or rebases with cherry-picks) to `master`.
- If multiple agents need to share scaffolding (e.g., test helpers in
  `tests/adversarial/helpers.c` referenced by both theorem harness and
  bisim harness), create the shared file FIRST in a pre-S75 prep commit,
  not during parallel dispatch.

### §7.3 Non-destructive operations

Per `feedback_user_favors_coherence_over_velocity.md`:
- Never force-push.
- Never `git reset --hard` across integration boundaries.
- Never amend commits that other agents may have branched from.
- Always prefer new commits over amending (Git Safety Protocol in
  CLAUDE.md).

### §7.4 Hook compliance

CLAUDE.md: never skip hooks (`--no-verify`) unless user explicitly asks.
If a pre-commit hook fails after Agent K's commit in this session or any S75
commit, **do not amend the offending commit**. Fix the underlying issue,
re-stage, create a NEW commit.

---

## §8. Closing orientation

S75 is the first session where ARCHIMATION starts shipping **validated** claims
rather than *asserted* claims. The theorem harness (Item 1) is the load-bearing
move: every Tier-1 item after it compounds on a foundation of "things that
demonstrably work" rather than "things that theoretically work."

Four honest checkpoints at the end of S75:

1. Are the 7 theorems demonstrably fired by adversarial cases? (Item 1)
2. Can the cortex enumerate its population by kind (Maturana-Varela
   Criterion 1)? (Item 2)
3. Is the APE regression resolved consistently across code + docs + paper?
   (Item 3)
4. Did we shift any Tier-3 item from "aspirational" to "in-progress"? (Items
   7-10)

If #1 and #3 land cleanly, S75 is enough to submit the minimum-publishable
paper (research-J §7). If #2 and #4 also land, we have the population census +
one moat-widening move in-flight for S76-S77.

The user wrote the paper. Our trust.ko cites it. S75 is where citation
becomes demonstration.

---

## §9. References — inter-document cross-reference

**Canonical architecture:** `docs/architecture-v2.md` (§§4, 6, 8, 10).

**Research reports** (`docs/research/s74_*.md`):
- A Von Neumann beyond (§2.5, §2.6 Monte Carlo)
- B Biology exact (§3 meiosis)
- C Endosymbiosis (§0.2 algedonic; §3(c) producer-consumer)
- D Crypto audit (§1.1 APE; §3.1 behavioral binding; §3.3 regression item 10)
- E Chromosomal model (§0 struct match; §4.5 meiosis rename; §3.6 conformance_quadrant)
- F Homoiconic ISA (§0 reject; §3 self-attestation; §7 dispatch rodata)
- G Reliability consensus (§0, §2.3, §2.4 quorum CFT-not-BFT)
- H Observation primitives (§1.1 library census; §1.5 algedonic; §1.6 Bennett depth)
- I Bisimulation (§0.1 empirical harness; §4 design)
- J Moat landscape (§5 5 proposals; §7 peer-review simulation)

**Prior roadmaps:**
- `docs/architecture-roadmap-s71.md` — 12-agent S71 research synthesis; Tier-1
  items preempted by S72 bootc pivot but still valid (linux-hardened opt-in,
  trust_lsm.c, pahole guard, BTRFS installer).
- `docs/architecture-meta-exploit-s73.md` — 12-framework synthesis that
  predicted the tissue-cortex-measurement loop; the S74 feature agents 5-9
  implemented this directly.

**Behavioral memory:**
- `memory/feedback_user_favors_coherence_over_velocity.md` — user strategic
  preference; re-read before every S75 dispatch decision.
- `memory/roa_paper_validation_tier_audit_and_s74_plan.md` — prior session
  strategic alignment; §6 "documentation gaps" list inherits directly to S75
  open items.

**Integration brief:** `docs/agent10_integration_brief.md` — Agent K's S74
close-out scope; S75 starts at the commit boundary Agent K produces.

---

**End of s75_roadmap.md.**
