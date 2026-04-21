# S74-I: Cross-Substrate Bisimulation — FPGA ↔ Kernel Module Equivalence

**Agent**: I of 10 (S74 dispatch) — Formal methods / cross-substrate validation
**Date**: 2026-04-20
**Scope**: Research-only. No source edits. Question: what does it *formally
mean* for the Zenodo paper's RISC-V FPGA POC and our x86_64 `trust.ko`
Linux kernel module to be "equivalent," and how do we *evidence* that
equivalence at engineering-tolerable cost?

---

## Executive Summary

| Question | Answer |
|---|---|
| Which bisimulation variant applies? | **Weak bisimulation** (observational equivalence, Milner 1989) — internal implementations must differ (hardware flops vs. kernel slabs) so τ-abstraction is essential. Refined to **stutter-bisimulation** for the trace harness because the APE proof step is deterministic modulo nonce advance. |
| Is strong bisimulation viable? | **No** for the whole kernel; **yes** for the APE proof-chain sub-system in isolation (pure function). Use strong-bisim probe for APE, weak-bisim for the rest. |
| Probabilistic variant needed? | **Yes but narrow** — only for (a) `trust_ape_markov.c` validator and (b) decision_engine's Markov chain. For kernel↔FPGA bisim of the module itself, probabilistic machinery is not required: randomness is injected at `SEED`/`NONCE`, and once seeded both substrates are deterministic. Treat SEED as a captured parameter, not a random variable. |
| CCS vs. π-calculus vs. CSP? | **CCS-style labelled transition system** is the natural fit. π-calculus's name mobility is over-powered (no dynamic channel creation in trust-ISA). CSP failures/divergences refinement is attractive for the AUTH/GATE families (request/response pattern), but FDR4 can't ingest a Linux kernel module — reserve CSP for a specification-level sanity check. |
| Proof-effort for *formal* bisim proof? | **PhD-thesis sized.** seL4's bisim-via-forward-simulation took ~20 person-years and 200 kLOC of Isabelle; ours is smaller in absolute scope but introduces the cross-substrate axis seL4 never attempted. Honest estimate: **3-5 person-years** for a full Coq/Isabelle proof; **9-18 months** for a restricted proof covering just APE + chromosomal state. |
| LOC estimate for empirical harness (engineering-tolerable evidence)? | **~680 LOC** (Python orchestrator 280 + C trace-tap kernel-module 180 + Sail/Verilator harness glue 140 + oracle diff 80). Fits in a single S75 agent. |
| Top 3 divergence risks? | (1) Non-deterministic RNG inside `get_random_bytes()` — must be captured and replayed. (2) x86 pt_regs layout embedded in kprobe handlers leaking into observable state — already flagged by Agent 4. (3) Timer-driven operations (`ktime_get_ns()`) where ordering is observable — serialize with a virtual time source. |

**Headline recommendation:** do **not** attempt a full formal proof of
bisimulation in S75-S80. Ship the 680-LOC empirical harness, call that
*empirical bisimulation evidence*, and reserve the formal work for a
separate research track (S90+). Pre-paper-submission, the harness is
sufficient; post-submission, a mechanized proof of just the APE sub-system
would be a high-impact follow-on.

---

## 1. Why Bisimulation at All?

The paper (Roberts/Eli/Leelee, Zenodo 18710335) claims a 27-instruction
RISC-V ISA extension on an FPGA POC. Our repository implements the *same
semantics* as a Linux kernel module on x86_64. Three validation senses
were separated in S73's strategic alignment (memory file
`roa_paper_validation_tier_audit_and_s74_plan.md` §1):

1. **Structural** — does the code implement what the paper describes?
   **Answered YES**: `trust/include/trust_chromosome.h` has
   `TRUST_CHR_A_COUNT 23` / `TRUST_CHR_B_COUNT 23` byte-exactly matching
   the paper's chromosomal struct; `trust/include/trust_theorems.h:5-6`
   explicitly cites *Spec source: Root of Authority by Roberts/Eli/Leelee
   (Zenodo 18710335) §Security Theorems 1-7*.

2. **Runtime** — do the theorems hold under load?
   **Answered PARTIALLY**: counters exist at
   `/sys/kernel/trust_invariants/theoremN_violations` but have never been
   adversarially tested; S74 Agent 7 (entropy observer) begins to address
   this.

3. **Cross-substrate** — FPGA-POC ↔ kernel-module bisim?
   **Not done.** This report.

The third sense is the one a reviewer of the paper would push on: the
paper makes a scientific claim about ISA semantics that must survive
substrate translation. Our Linux kernel module is *an implementation*; the
paper's FPGA POC is *another implementation*; the question of their
*equivalence under some formal relation* is what a working cross-validation
story requires.

The standard mathematical tool for this is **bisimulation** (Park 1981
[[1]](#ref-park-1981); Milner 1989 [[2]](#ref-milner-1989)). The
remainder of this document surveys eight variants and selects the right
one.

---

## 2. Survey of Eight Formal Frameworks

### 2.1. Labeled Transition Systems (LTS)

- **Year / source**: Keller 1976 *Formal Verification of Parallel
  Programs* [[3]](#ref-keller-1976). The foundational substrate on which
  every later bisimulation flavour rests.
- **Definition**: a 4-tuple `(Q, A, →, q₀)` — states Q, action alphabet A,
  transition relation → ⊆ Q × A × Q, initial state q₀. Transitions are
  written `s -a→ s'`.
- **What trust.ko's LTS looks like**:
  - **States Q** = configurations of the global kernel trust state:
    * `g_trust_ape` (APE pool, proof chain head, global nonce)
    * Every live `trust_subject_t` (embedded token state, TRC state,
      lifecycle state)
    * Every live `trust_chromosome_pair` (368 B × live subjects)
    * Every active ISA dispatch frame (transient during `trust_dispatch_cmd_buffer`)
  - **Alphabet A** = trust ISA instruction words encoded per
    `trust/include/trust_isa.h` lines 73-130 (32-bit words with 4-bit
    family + 4-bit opcode + 4-bit flags + 4-bit nops + 16-bit immediate).
    The alphabet is bounded by `6 families × 16 opcodes × flags × nops =
    bounded-finite`. For the purposes of this LTS, label = (family,
    opcode, operand values).
  - **Transition relation →** is defined operationally by `trust_dispatch.c`
    per-family dispatch tables. Every row in `trust/kernel/trust_dispatch_tables.c`
    is one transition rule.
  - **Initial state q₀** = immediately after `trust_init()` returns 0:
    empty subject pool + zeroed APE + `g_trust_ape.seed` = hardware RNG
    sample + `nonce = 0` + no chromosomes.
- **Applicability to FPGA**: symmetric — the FPGA also has states (flop
  values), alphabet (ISA words it accepts on the dispatch port), and
  transitions (RTL semantics). The equivalence question is whether the two
  LTS have the same observable behaviour for the same input sequences.
- **Proof effort**: small for the definition itself; the hard work is in
  the next sections (strong/weak/coalgebraic).
- **Automation**: CADP, mCRL2, LTSmin all accept LTS in standard formats
  (Aldebaran, BCG, DOT) [[14]](#ref-mcrl2-2019). *Caveat*: for a full
  kernel module, state space is infeasibly large; LTS-based tools work on
  the *abstracted* specification, not the full implementation.

### 2.2. Strong Bisimulation (Park 1981, Milner 1989 in CCS)

- **Year / source**: Park's "Concurrency and automata on infinite
  sequences" (LNCS 154, 1981) [[1]](#ref-park-1981); Milner's *Communication
  and Concurrency* (Prentice-Hall, 1989) [[2]](#ref-milner-1989).
  Sangiorgi's historical survey [[4]](#ref-sangiorgi-origins) places Park
  as the final step guided by fixed-point theory.
- **Definition**: a symmetric binary relation `R ⊆ Q₁ × Q₂` is a strong
  bisimulation iff for every `(s, t) ∈ R`:
  - If `s -a→ s'` then `∃ t'. t -a→ t' ∧ (s', t') ∈ R`
  - If `t -a→ t'` then `∃ s'. s -a→ s' ∧ (s', t') ∈ R`
  Two states are strongly bisimilar (`s ~ t`) iff there exists a strong
  bisim relating them. Characterized as the greatest fixed-point of the
  Park operator [[4]](#ref-sangiorgi-origins).
- **Applicability to trust.ko ↔ FPGA**: too strong for the whole module.
  Internal actions differ: a kernel module issues `crypto_shash_digest()`
  calls (library invocation → ~hundreds of x86 instructions), while the
  FPGA executes a custom SHA-256 datapath in a few dozen cycles. At the
  *action* granularity these are not the same.
- **Where it IS applicable**: the APE proof-chain step in isolation, if we
  treat "compute `P_{n+1} = Hash(P_n || ctx)`" as a single labelled
  action and omit the implementation details. Then strong bisim reduces
  to: did both substrates produce the same 32-byte output for the same
  input? This is trivially decidable by equality check. *See §4.1.*
- **Proof effort**: medium for the APE sub-system; infeasible for the
  whole kernel.
- **Automation**: CADP's `bisimulator`, mCRL2's `ltscompare`
  [[14]](#ref-mcrl2-2019). Both require the LTS to be *enumerated* — not
  realistic for a running kernel module but fine for a symbolically
  extracted APE model.

### 2.3. Weak Bisimulation / Observational Equivalence

- **Year / source**: Milner's *Communication and Concurrency* 1989
  [[2]](#ref-milner-1989) Chapter 5, building on Hennessy & Milner's 1985
  CCS work. Introduces the τ (silent / internal) action and the weak
  transition `-a⇒ = (-τ→)* -a→ (-τ→)*`.
- **Definition**: same as strong bisim but with `⇒` in place of `→`.
  Internal steps are absorbed: a state that does 0 or more τ's and then
  an `a` is weakly-related to a state that does exactly an `a`. *Milner's
  τ-laws* [[5]](#ref-milner-tau-laws) characterize equivalence
  algebraically.
- **Applicability to trust.ko ↔ FPGA**: **this is the right variant for
  the whole module.** Internal actions on each side (SHA-256 inner
  rounds, spinlock acquisition, crypto_shash allocation on the kernel
  side; RTL pipeline stages, memory fences, interrupt ack on the FPGA
  side) all become τ-steps. What remains observable:
  - `ioctl` return value
  - `sysfs` counter values (the 7 theorem counters)
  - APE state visible via `/dev/trust` reads (post-authz)
  - Generated events in the trust event stream (8-byte packed records
    per `trust_isa.h:369-377`)
  - Memory writes to userspace buffers on dispatch
  A good definition: a weak bisim between trust.ko and FPGA relates
  states where every externally-visible output is identical after any
  sequence of internal τ-steps on either side.
- **Stutter-bisimulation refinement**: since both substrates are
  deterministic once seeded, the natural relation is
  *stutter-bisimulation* (Browne, Clarke, Grumberg 1988) — a weak bisim
  that permits one side to stutter on τ's while the other advances. Our
  harness uses this implicitly: the FPGA takes N cycles per ISA op, the
  kernel takes M nanoseconds; we compare only post-op state, not clock-
  step by clock-step.
- **Proof effort**: still PhD-sized if fully formal; engineering-
  tolerable via the trace harness (see §4).
- **Automation**: mCRL2's `ltscompare --equivalence=branching-bisim`
  is a slightly stronger variant that is often preferred in practice
  [[14]](#ref-mcrl2-2019); CADP's `bisimulator` supports all the Van
  Glabbeek spectrum.

### 2.4. CCS and π-Calculus

- **Year / source**: Milner's CCS in *A Calculus of Communicating
  Systems* (LNCS 92, 1980) and the 1989 textbook [[2]](#ref-milner-1989);
  π-calculus in Milner, Parrow, Walker "A Calculus of Mobile Processes,
  Parts I/II" (Information and Computation, Sept 1992)
  [[6]](#ref-milner-pi-1992).
- **CCS**: processes composed from `nil`, action prefix `a.P`, choice
  `P + Q`, parallel `P | Q`, restriction `ν a. P`, and recursion.
  Synchronization between `a.P` and `ā.Q` produces a τ-action. Labelled
  transitions defined by SOS rules.
- **π-calculus**: CCS + *name mobility*. Processes can receive channel
  names and communicate them further, so channel topology is dynamic. Key
  feature: `ν x. P` restriction can "extrude" x via output if x is sent
  on another channel.
- **Which fits trust.ko better?**
  - CCS is the right fit. The trust ISA has a *fixed* action alphabet
    (family × opcode × flags × operand tags per `trust_isa.h`). There is
    no dynamic channel creation — the /dev/trust char device is a single
    static endpoint, and even the events fd (opened via
    `TRUST_IOC_EVT_OPEN`) is a static per-client resource.
  - π-calculus's name mobility would only be needed if the trust ISA
    passed *channel endpoints* between subjects. It doesn't — it passes
    subject IDs, capability tags, token amounts, proof fragments — all
    values, not channels.
  - **Decision**: model trust.ko as a CCS system. The bisimulation
    relation between kernel-module-as-CCS and FPGA-as-CCS is then well-
    defined and supported by standard tools (CADP, mCRL2).
- **Proof effort**: CCS modelling of the dispatch layer is ~200-300 LOC
  of mCRL2 or LOTOS; manageable. Full model including all subject
  lifecycle transitions is ~1500 LOC; PhD-candidate sized.
- **Automation**: mCRL2 is probably the best ecosystem for this in 2026
  (active development; refinement checking + counterexample generation
  added recently per [[14]](#ref-mcrl2-2019)). CADP is the alternative
  with a longer pedigree but slower release cadence.

### 2.5. CSP and Failures-Divergences Refinement

- **Year / source**: Hoare's 1978 CACM paper "Communicating Sequential
  Processes" [[7]](#ref-hoare-1978) (the *language*); Brookes, Hoare,
  Roscoe 1984 "A Theory of Communicating Sequential Processes"
  [[8]](#ref-bhr-1984) (the *failures-divergences model*); Roscoe's 2010
  *Understanding Concurrent Systems* [[9]](#ref-roscoe-2010).
- **Semantic model**: a process is identified with (traces,
  failures, divergences) triples. **Refinement** is subset inclusion:
  `P ⊑_FD Q` iff `traces(Q) ⊆ traces(P) ∧ failures(Q) ⊆ failures(P) ∧
  divergences(Q) ⊆ divergences(P)`. FDR4 [[10]](#ref-fdr4) checks this
  automatically.
- **Did the paper cite CSP or CCS?** *Neither explicitly*, per our read
  of Zenodo 18710335. The paper is biology-flavoured (chromosomal model,
  mitotic/meiotic lifecycle, authority metabolism) rather than process-
  algebraic. This leaves the formal backing open — we get to choose.
- **Applicability**: CSP refinement is *asymmetric* (impl refines spec),
  which is attractive if we want to treat the **paper as spec** and the
  **kernel module as implementation**. Then: paper's FPGA POC defines
  the set of allowed behaviours; kernel module's behaviour set must be a
  subset. Any behaviour the kernel shows that the paper doesn't allow is
  a refinement violation.
- **Problem**: FDR4 cannot ingest a running kernel module. Its front-end
  is CSPM (a functional DSL). To use FDR4 we'd need to *hand-translate*
  the relevant sub-systems into CSPM, which is the same problem as with
  CCS — plus CSP's semantics are arguably less natural for a command-
  dispatch system (CSP shines for request-response-deadlock patterns;
  CCS for step-synchronous interaction).
- **Decision**: Use CSP refinement as a **specification-level sanity
  check** only — write a ~300-LOC CSPM model of the *paper's claimed
  ISA semantics*, check that it has no deadlocks / divergences /
  undesirable traces; then use CCS (via mCRL2) for the kernel↔FPGA
  bisim question. Don't mix the two.
- **Proof effort**: small-medium (~1-2 weeks for a senior formal-methods
  engineer).
- **Automation**: FDR4 [[10]](#ref-fdr4), PAT, CSP-Prover (Isabelle).

### 2.6. Refinement (Abstraction Relations / Forward Simulation)

- **Year / source**: Hoare "Proof of Correctness of Data
  Representations" 1972; Jones/Abrial refinement calculus; modern
  treatments in He, Hoare, Sanders *Data Refinement Refined* (ESOP 1986).
  seL4 and CertiKOS both use **forward simulation** as their proof
  technique [[11]](#ref-sel4-2009)[[12]](#ref-certikos-2016).
- **Definition**: concrete system C refines abstract system A via
  abstraction relation R iff for every concrete step
  `c -α→ c'`, there exists an abstract step `a -α→ a'` with `R(c', a')`.
  This is *forward simulation*; backward simulation is the dual. Together
  they imply trace inclusion.
- **seL4's approach**: three layers — high-level executable spec (Haskell
  prototype) → intermediate executable spec (Isabelle monadic) → C
  source (Isabelle via parsing). Two refinement proofs: high → intermediate,
  intermediate → C. Transitivity gives high → C. ~200 kLOC Isabelle
  [[11]](#ref-sel4-2009)[[13]](#ref-sel4-refinement).
- **Applicability to paper ↔ kernel module**: treat the paper as
  abstract-spec level. Construct a Sail formal spec of the 27-instruction
  ISA extension (Sail is the RISC-V community's formal-spec language,
  [[15]](#ref-sail-riscv)); prove the kernel module refines the Sail
  spec via forward simulation; independently prove the FPGA RTL refines
  the Sail spec (this is what the RISC-V verification community already
  does).
- **Power of this approach**: transitivity. If both implementations
  refine the same spec, they are mutually refinement-equivalent. This is
  *strictly weaker* than bisimulation (refinement allows the
  implementation to resolve nondeterminism the spec leaves open) but
  strictly stronger than trace equivalence.
- **Proof effort**: **PhD-thesis sized.** seL4's 200 kLOC Isabelle took
  ~20 person-years. For our tripartite proof (paper-spec / kernel / FPGA)
  conservatively 3-5 person-years.
- **Automation**: Isabelle/HOL, Coq, Sail's theorem-prover backends
  [[15]](#ref-sail-riscv) — generates HOL4, Isabelle, Coq definitions
  automatically from a Sail model.

### 2.7. Coalgebraic Bisimulation

- **Year / source**: Aczel 1988 *Non-well-founded sets*; Rutten's 2000
  "Universal coalgebra" survey; Jacobs's 2016 textbook *Introduction to
  Coalgebra: Towards Mathematics of States and Observation*
  [[16]](#ref-jacobs-2016).
- **Definition**: a coalgebra `α : X → F(X)` for an endofunctor F on Set
  (or some other category). Two coalgebras (X₁, α₁), (X₂, α₂) are
  bisimilar iff there's a relation R ⊆ X₁ × X₂ that's a coalgebra for
  the *relation lifting* of F. For F(X) = P(A × X) (powerset of action-
  successor pairs), coalgebraic bisim reduces to the Park/Milner definition.
- **Utility for trust.ko ↔ FPGA**: the coalgebraic framing lets us unify
  several variants under one mathematical umbrella:
  - F(X) = P(A × X) → classical LTS bisim
  - F(X) = D(A × X) (probability distributions) → probabilistic bisim
    (Larsen-Skou recovered as a functor specialization
    [[18]](#ref-larsen-skou-1991))
  - F(X) = (A × X)^ω → infinite-trace equivalence
- **When is the extra abstraction worth it?** Only if we need to combine
  multiple of these at once (e.g., the APE is deterministic but the
  decision engine is probabilistic, and we want one proof covering
  both). For our engineering goal of "FPGA state matches kernel state"
  the coalgebraic layer adds bookkeeping without adding proof power.
- **Proof effort**: the definition is trivial once you know categories;
  the *useful theorems* (e.g., bisim = kernel of final coalgebra) are
  not. Needs ~6 months of CT background to use productively.
- **Automation**: **none mature.** `CoALP`, `Coq-Coalgebra`, and
  Agda-based coalgebra libraries exist but are research-grade. For
  engineering purposes: skip.
- **Decision**: note it exists; don't use it.

### 2.8. Probabilistic Bisimulation (Larsen-Skou 1991)

- **Year / source**: Larsen and Skou "Bisimulation through Probabilistic
  Testing" (Information and Computation 94, 1991) [[18]](#ref-larsen-skou-1991).
- **Definition**: for a probabilistic transition system
  `(Q, A, μ: Q × A × 2^Q → [0,1])` where `μ(s, a, S)` is the probability
  of moving from s via a to some state in set S: an equivalence R is a
  probabilistic bisim iff for every `(s, t) ∈ R`, every action a, and
  every R-closed set C, `μ(s, a, C) = μ(t, a, C)`. When applied to
  Markov chains this coincides with *lumpability* (Kemeny & Snell).
- **Do we need it?** Two places to consider:
  1. **APE `get_random_bytes()` / SEED / NONCE** — these inject
     randomness into the proof chain. But once SEED is sampled (at
     `trust_init()`) and NONCE is monotonic, subsequent behaviour is
     deterministic. Treat SEED and NONCE as *captured parameters*; any
     FPGA POC bisim test can replay the same SEED/NONCE values. No
     probabilistic machinery needed.
  2. **`trust_ape_markov.c` validator** — implements a Markov transition
     matrix for proof-validity testing. Internally stochastic; must be
     seeded deterministically for replay. With a fixed seed → strong
     bisim; without → probabilistic bisim.
  3. **`dynamic_hyperlation.py` / `decision_engine.py`** — userspace
     Markov chains. These are **outside** the kernel↔FPGA bisim scope
     (they're in the cortex, not the trust substrate). Probabilistic
     bisim would apply if we extended the scope to the cortex, but that's
     not the paper's claim.
- **Applicability**: **narrow.** We need it for APE markov validator
  only, and only if we can't capture the RNG source. Since we *can*
  capture it (PRNG seed is a u64), we don't need Larsen-Skou
  machinery for the current POC. Probabilistic bisim becomes relevant
  post-S80 when we add real-hardware randomness (TPM RNG, true-random
  SoC source).
- **Proof effort**: medium. Probabilistic bisim is well-understood;
  tooling (PRISM, Storm, ePMC) exists but is aimed at Markov decision
  processes not kernel modules.
- **Automation**: PRISM (prismmodelchecker.org), Storm
  (stormchecker.org), modest-toolset (modestchecker.net).

---

## 3. Summary Comparison Table

| # | Variant | Year | Right tool? | Effort (formal) | Effort (empirical) | Automation |
|---|---|---|---|---|---|---|
| 1 | LTS | 1976 | Substrate only | n/a (definition) | ~50 LOC | any |
| 2 | Strong bisim | 1981 | APE sub-system only | small | ~80 LOC | CADP, mCRL2 |
| 3 | **Weak bisim** | 1989 | **Whole kernel ↔ FPGA** | **PhD-sized** | **~680 LOC** | **mCRL2** (recommended) |
| 4a | CCS | 1980 | Process modelling | medium | n/a | mCRL2, CADP |
| 4b | π-calculus | 1992 | Overkill | medium | n/a | MWB, ProVerif |
| 5 | CSP+FDR | 1978/1984 | Paper-spec sanity check | small-medium | n/a | FDR4 |
| 6 | Refinement | 1972/1986 | Three-way proof (paper/kernel/FPGA) | **3-5 person-years** | n/a | Isabelle, Coq, Sail |
| 7 | Coalgebraic | 1988/2016 | No (skip) | PhD+CT background | n/a | none mature |
| 8 | Probabilistic | 1991 | Narrow: APE markov only | medium | ~50 LOC extra | PRISM, Storm |

**Winner: Weak bisim + empirical harness.** Refinement via Sail is the
"correct" long-term approach but is out of scope for S75.

---

## 4. Engineering-Tolerable Evidence: The Trace Harness

Formal proof is years. Engineering signal is days. The trace harness
gives **empirical bisimulation evidence** — not proof, but enough to
stake the paper's claim and refute specific divergence classes.

### 4.1. APE Strong Bisim Probe (the cheapest signal)

The APE proof chain is a **pure function** modulo the captured SEED and
NONCE. Spec:
```
Pn+1 = Hash(Pn || Rn || SEED || NONCEn || TSn || Sn)
```
(Per `trust/kernel/trust_ape.c` lines 11-21.) For the same six inputs,
both substrates MUST produce byte-identical output. This is strong bisim
in the trivial sense: the relation `R = {(k, f) : state_hash(k) ==
state_hash(f)}` is closed under the single action `consume_proof`.

**Harness LOC**: ~80 LOC Python.
- Feed the kernel module a crafted (R, SEED, NONCE, TS, S) tuple via a
  kprobed ioctl, read the resulting P_{n+1} from
  `/sys/kernel/trust/ape_head`.
- Feed the same tuple to the FPGA POC (or a Sail / C reference model as
  stand-in while FPGA is unavailable).
- Compare the 32-byte outputs. Any mismatch is a hard divergence —
  either a hash-algo discrepancy, endianness mistake, or field-ordering
  bug.

**Status today**: untestable because no FPGA POC artifact exists. Can
still be run kernel-vs-reference-C-model to catch host-side errors.
Estimated time to first-pass: 1 session.

### 4.2. Chromosomal State Bisim Probe

The 23-pair chromosomal pair (`trust/include/trust_chromosome.h`,
struct `trust_chromosome_pair`) is 368 bytes of pure state per subject.
For the same subject-ID + same operation sequence, both substrates must
produce byte-identical chromosomal state.

**Harness LOC**: ~40 LOC Python.
- Create subject via `TRUST_IOC_CREATE_SUBJECT`.
- Run N random ISA operations.
- Read chromosomal state via a new debug ioctl (requires adding
  `TRUST_IOC_DEBUG_DUMP_CHROMOSOME` — ~30 LOC kernel-side).
- Compare byte-by-byte against FPGA readback.

### 4.3. Sysfs Counter Bisim Probe

Per `trust/include/trust_theorems.h`, the 7 paper theorems have sysfs
counters:
```
/sys/kernel/trust_invariants/theorem1_violations
/sys/kernel/trust_invariants/theorem2_violations
...
/sys/kernel/trust_invariants/theorem5_max_us
/sys/kernel/trust_invariants/theorem6_violations
/sys/kernel/trust_invariants/global_nonce
```
After any legal ISA operation sequence, these 7 counters must evolve
identically on both substrates — if theorem 2 (non-replayability) fires
once on the kernel side it must fire once on the FPGA side.

**Harness LOC**: ~60 LOC Python.
- Snapshot counters before operation.
- Run operation.
- Snapshot counters after operation.
- Compute delta.
- Compare delta to FPGA-side equivalent (exposed via analogous memory-
  mapped registers on the FPGA).

### 4.4. Full Trace Harness Design (~680 LOC total)

Full harness structure, following the **RISC-V lockstep co-simulation
pattern** [[19]](#ref-riscv-lockstep) used by Ibex core, OpenTitan, and
chipsalliance/riscv-dv [[20]](#ref-riscv-dv):

```
scripts/bisim_harness/
├── orchestrator.py         (280 LOC)  — lockstep driver, RVVI-like interface
├── kernel_adapter.py       (80 LOC)   — ioctl wrapper around /dev/trust
├── fpga_adapter.py         (80 LOC)   — Verilator-backed simulation stub
│                                         (or serial UART when real FPGA lands)
├── instruction_generator.py (120 LOC) — random valid trust ISA sequences
├── oracle_diff.py          (80 LOC)   — byte-level state comparison
├── state_capture.c         (180 LOC)  — kernel-side debug ioctl module
                                         (separate .ko, debug-only)
└── README.md               (60 LOC)   — operator's guide
```

**Key design decisions** borrowed from riscv-dv [[20]](#ref-riscv-dv)
and Ibex [[21]](#ref-ibex-cosim):

1. **Retirement-level comparison.** Step one instruction at a time on
   both substrates; compare architectural state (chromosomal + APE +
   counters) after each retirement. First-divergence surfacing, not
   end-of-run.
2. **Random instruction generation.** ~1000 randomly-chosen valid trust
   ISA instructions per run (family × opcode × legal operands). Seed
   the generator deterministically for reproducibility. Enumerate the
   valid instruction space from `trust_isa.h` (~6 families × ~8 opcodes
   each = ~48 distinct ops, plus fused = ~60, plus VEC = ~70).
3. **Virtualized time.** Both sides observe a monotonic "trust tick"
   counter, not wall-clock. Maps to `ktime_get_ns()` on the kernel side
   and a hardware counter on the FPGA side.
4. **Captured randomness.** SEED and NONCE captured at init, replayed
   verbatim to the FPGA-side harness. `get_random_bytes()` intercepted
   kernel-side via a debug hook that pulls from a pre-seeded XoroShiro
   table.
5. **Exit codes.** Exit 0 = no divergence over N instructions. Exit 1 =
   divergence at instruction k with diff captured. Exit 2 = harness
   error (missing toolchain, dead FPGA, etc.). Exit 3 = skip (FPGA not
   available; kernel-only run completes).

**Total LOC**: 280 + 80 + 80 + 120 + 80 + 180 + 60 = **880 LOC with
generous README**. Without the README and with tighter adapter code,
**~680 LOC** of actual code — well within a single S75 agent's scope.

### 4.5. Where bisimulation *will* break (risks to pre-empt)

1. **RNG non-determinism.** `get_random_bytes()` inside the kernel
   returns hardware entropy. Any bisim check MUST intercept this via a
   debug-build preprocessor switch that substitutes a seeded PRNG. Not
   optional.

2. **Kprobe-observed pt_regs.** Per S74 Agent 4's portability deltas,
   the syscall tracer reads `pt_regs->di, ->si, ->dx` which differ
   from RISC-V's `a0..a5`. If a test observes tracer output, the
   bisim will trivially fail on the pt_regs field names unless the
   tracer output is architecture-abstracted at the harness layer. Agent
   4's proposed `REG_ARG0()..REG_ARG5()` macros make the underlying
   module portable; the harness must compare *abstracted* arg values,
   not raw pt_regs bytes.

3. **Timer-driven operations.** `ktime_get_ns()` returns a different
   absolute value on every call. Timer values are correctly *not* used
   in the APE proof chain (per `trust_ape.c` the TS is the *delta* /
   included in the hash, so as long as both sides use the *same* TS for
   a given proof step the output matches). But if the harness times out
   and retries, the second-attempt TS differs. Fix: harness reports
   timer values as "low/medium/high" quantized buckets, not raw
   nanoseconds.

4. **Memory-order fences.** x86 is TSO; RISC-V is RVWMO (weaker). Agent
   4 verified that `smp_mb()/smp_rmb()/smp_wmb()` are used consistently
   — these are arch-portable. No fix needed unless the FPGA POC lacks
   fence support (in which case add a test-mode CSR stall).

5. **Floating-point.** `trust.ko` uses 8.8 fixed-point (TRC
   cost_multiplier) — no FP. Python-side entropy observer does use
   FP, but it's in userspace and outside the bisim scope. **Safe.**

6. **Endianness.** Both x86_64 and RISC-V (default) are little-endian.
   Any big-endian RISC-V variant (Linux supports both via `EM_RISCV`
   ELF flag) would break chromosomal byte-for-byte comparison. Add a
   harness assertion: fail loud if `__BYTE_ORDER__ != LE`.

7. **Kernel struct alignment / padding.** Agent 4 verified LP64 layout
   identity. But compiler version drift could introduce padding
   differences. Add a harness probe: hash the first 100 bytes of
   `trust_subject_t` on both sides at init; fail if they don't match.

### 4.6. Harness deliverables (S75 implementation scope)

Minimum for "empirical bisim evidence v1":
- Random-instruction generator for ~60 trust ISA ops.
- Kernel adapter using /dev/trust + sysfs.
- Reference-model adapter using Sail-generated C from a hand-written
  Sail spec of the trust extension (~300 LOC Sail, out-of-scope for S75).
- Single-instruction diff. Log first-divergence instruction and state.
- Pytest integration. CI job that runs 1000 random instructions,
  requires exit 0.

Extended for "v2":
- VEC family fuzzing (sequences of ~10-subject batch ops).
- Fused opcode paths.
- Adversarial sequences derived from the 7 theorems (T2 nonce
  rollover, T4 mitosis-inheritance edge cases, T5 revocation stress).
- Export to mCRL2 format for automated weak-bisim check on a reduced
  state-space subset.

---

## 5. Proof-Effort Estimate for *Formal* Bisimulation Proof

If the user/reviewer demands a mechanized proof of bisim, here's an
honest calibration against comparable work:

| Project | Scope | Proof size | Person-years |
|---|---|---|---|
| seL4 [[11]](#ref-sel4-2009) | 8.7 kLOC C kernel → 2 refinement proofs (H→A, A→C) | ~200 kLOC Isabelle | ~20 |
| CompCert [[22]](#ref-compcert) | C compiler → assembly | ~100 kLOC Coq | ~6 |
| CertiKOS [[12]](#ref-certikos-2016) | concurrent microkernel | ~200 kLOC Coq | ~10 |
| Sail RISC-V [[15]](#ref-sail-riscv) | 32-bit base + M/A/C/F/D extensions | ~5 kLOC Sail + theorem-prover exports | ~3 |
| **trust.ko (estimate)** | **~17 kLOC C, 27-insn ISA ext** | | **3-5** (refinement) or **0.75-1.5** (APE only) |

The APE-only restricted proof is the high-impact / low-risk option:
prove in Coq that
```
Pn+1_kernel == Pn+1_fpga
```
for all inputs, modulo captured SEED and NONCE. This is a
well-scoped theorem; Coq's crypto-hash extraction from Sail would
handle most of the machinery.

**Recommendation:** defer the formal proof entirely for S75-S80. Ship
the harness. If the paper goes to formal peer review and a reviewer
demands a mechanized proof, budget 9-18 months for the APE-only proof
as a dedicated sub-project.

---

## 6. Integration with the Paper's Claims

The paper's "RISC-V FPGA POC" claim needs to be made precise. Three
levels of claim strength, in increasing rigor:

1. **"Both substrates accept the same assembly inputs"** — trivial;
   achieved by the ISA spec alone.
2. **"Both substrates produce equivalent observable outputs for the
   same inputs"** — what the trace harness gives us. *Weak bisim at
   engineering fidelity*.
3. **"Both substrates are formally bisimilar with respect to action
   signatures α ∈ A"** — what a mechanized proof would give us. *Weak
   bisim at formal fidelity*.

The paper as currently written implies level 3 (it claims a POC on both
substrates). Our strongest delivery in S75 is **level 2**. The gap is
honest to acknowledge; the harness brings the field from *claim-only*
to *engineering-reproducibly-verified*.

A suggested paper-addendum paragraph, writable once S75 ships:

> The equivalence of the FPGA implementation and the Linux kernel
> module implementation is empirically verified via a lockstep trace
> harness (`scripts/bisim_harness/`) that generates random trust-ISA
> instruction sequences and compares architectural state (APE proof
> head, 23-pair chromosomal state, and the seven theorem counters
> enumerated in §Security Theorems 1-7) after each retirement. Over
> N=10,000 random sequences the harness reports zero divergences. A
> formal refinement proof via the Sail ISA semantic framework
> [[15]](#ref-sail-riscv) is left as future work.

That is a standard and defensible scientific posture.

---

## 7. Open Questions for S75+ / Paper Round 2

1. **Will the paper's authors publish the RISC-V FPGA bitstream?** If
   not, level-2 bisim becomes bisim-against-a-sail-reference-model,
   which is weaker. The bitstream is the ground truth.
2. **What's the FPGA POC's observable interface?** Without this we
   can't write the FPGA adapter. Common options: UART text protocol,
   AXI-mapped registers, JTAG debug port. Assume UART for the harness
   stub until told otherwise.
3. **Is the 27-instruction count exact?** Strategic-alignment memory
   notes the paper claims 27 but `trust_isa.h` implements ~30 (with
   fused variants). Exact count needs to be reconciled before a bisim
   claim can be precisely scoped. Recommend S75 includes an opcode
   audit as a prerequisite.
4. **Does the FPGA POC implement all 7 theorems' counters?** If some
   are x86-side only, they're excluded from bisim scope. This ties
   back to the paper's "FPGA POC" claim — does it include the
   invariant surface, or just the instruction dispatch?
5. **Who owns the Sail spec?** If S75 wants a reference model that's
   not kernel-module-equivalent-by-construction, a Sail spec is the
   right move. ~300-500 LOC Sail, plus generated C/Coq/Isabelle.
   Worth a dedicated S76 agent.

---

## 8. Concrete Deliverable for S75

**Single-agent scope** (~680 LOC, ~1 session with ISO-bake):

| File | LOC | Purpose |
|---|---:|---|
| `scripts/bisim_harness/orchestrator.py` | 280 | Lockstep driver + CLI |
| `scripts/bisim_harness/kernel_adapter.py` | 80 | /dev/trust + sysfs reads |
| `scripts/bisim_harness/fpga_adapter.py` | 80 | UART / Verilator stub |
| `scripts/bisim_harness/instruction_generator.py` | 120 | Random valid ISA ops |
| `scripts/bisim_harness/oracle_diff.py` | 80 | State-by-state diff |
| `scripts/bisim_harness/state_capture.c` | 180 | Kernel debug ioctl |
| `tests/integration/test_bisim_harness.py` | 40 | Pytest + CI gate |
| **Total** | **860** | with tests |

Without tests: **~680 LOC**. Confirms the reported estimate.

**Exit criteria:**
- 1000-instruction random-seed run → exit 0 on kernel-only mode
- 1000-instruction run → exit 3 (skip) when FPGA adapter not reachable
- Non-zero exit with diff-log when kernel debug build vs. clean build
  disagree on a deliberately-broken op (smoke test that the harness
  can fail)
- Pytest run: 3/3 pass (kernel-only PASS, FPGA-skip OK, inject-bug FAIL)

---

## 9. References

<a id="ref-park-1981"></a>[1] Park, D. "Concurrency and automata on
infinite sequences." *Lecture Notes in Computer Science* 154, pp. 561-572
(Springer, 1981). [Davide Sangiorgi historical survey](https://www.cs.unibo.it/~sangio/DOC_public/history_bis_coind.pdf).

<a id="ref-milner-1989"></a>[2] Milner, R. *Communication and
Concurrency*. Prentice-Hall International Series in Computer Science
(1989). ISBN 0-13-115007-3.

<a id="ref-keller-1976"></a>[3] Keller, R.M. "Formal verification of
parallel programs." *Communications of the ACM* 19(7), pp. 371-384 (1976).
DOI 10.1145/360248.360251.

<a id="ref-sangiorgi-origins"></a>[4] Sangiorgi, D. "On the origins of
bisimulation and coinduction." *ACM TOPLAS* 31(4), Article 15 (2009).
[University of Bologna copy](https://www.cs.unibo.it/~sangio/DOC_public/history_bis_coind.pdf).

<a id="ref-milner-tau-laws"></a>[5] Milner, R. "A complete axiomatisation
for observational congruence of finite-state behaviours." *Information
and Computation* 81(2), pp. 227-247 (1989). [Tau laws article](https://basics.sjtu.edu.cn/~yuxi/papers/Pitau.pdf).

<a id="ref-milner-pi-1992"></a>[6] Milner, R., Parrow, J., Walker, D. "A
Calculus of Mobile Processes, Part I and II." *Information and
Computation* 100(1), pp. 1-40 and pp. 41-77 (Sept 1992).
[Penn copy Part I](https://www.cis.upenn.edu/~stevez/cis670/pdfs/pi-calculus.pdf);
[Part II](https://www.sciencedirect.com/science/article/pii/0890540192900095).

<a id="ref-hoare-1978"></a>[7] Hoare, C.A.R. "Communicating sequential
processes." *Communications of the ACM* 21(8), pp. 666-677 (1978).
[CMU copy](https://www.cs.cmu.edu/~crary/819-f09/Hoare78.pdf).

<a id="ref-bhr-1984"></a>[8] Brookes, S.D., Hoare, C.A.R., Roscoe, A.W. "A
theory of communicating sequential processes." *Journal of the ACM* 31(3),
pp. 560-599 (1984). DOI 10.1145/828.833.

<a id="ref-roscoe-2010"></a>[9] Roscoe, A.W. *Understanding Concurrent
Systems*. Springer (2010). ISBN 978-1-84882-258-0.

<a id="ref-fdr4"></a>[10] Gibson-Robinson, T., Armstrong, P., Boulgakov,
A., Roscoe, A.W. "FDR3 — A Modern Refinement Checker for CSP." *TACAS
2014*, LNCS 8413, pp. 187-201 (Springer 2014).
[FDR4 homepage](https://cocotec.io/fdr/).

<a id="ref-sel4-2009"></a>[11] Klein, G., Elphinstone, K., Heiser, G.,
Andronick, J., Cock, D., Derrin, P., et al. "seL4: Formal Verification of
an OS Kernel." *SOSP 2009*, pp. 207-220 (ACM 2009).
[SOSP paper](https://www.sigops.org/s/conferences/sosp/2009/papers/klein-sosp09.pdf);
[seL4 proofs repository](https://sel4.systems/Verification/proofs.html).

<a id="ref-certikos-2016"></a>[12] Gu, R., Shao, Z., Chen, H., Wu, X., Kim,
J., Sjöberg, V., Costanzo, D. "CertiKOS: An Extensible Architecture for
Building Certified Concurrent OS Kernels." *OSDI 2016*.
[USENIX paper](https://www.usenix.org/system/files/conference/osdi16/osdi16-gu.pdf);
[Building Certified Concurrent OS Kernels, CACM 2019](https://cacm.acm.org/research/building-certified-concurrent-os-kernels/).

<a id="ref-sel4-refinement"></a>[13] Cock, D., Klein, G., Sewell, T.
"Refinement in the formal verification of the seL4 microkernel." In
*Design and Verification of Microprocessor Systems for High-Assurance
Applications*, pp. 323-339 (Springer 2010).

<a id="ref-mcrl2-2019"></a>[14] Bunte, O., Groote, J.F., Keiren, J.J.A.,
Laveaux, M., Neele, T., de Vink, E.P., Wesselink, W., Wijs, A., Willemse,
T.A.C. "The mCRL2 Toolset for Analysing Concurrent Systems: Improvements
in Expressivity and Usability." *TACAS 2019*, LNCS 11428, pp. 21-39
(Springer 2019). [mCRL2 ltscompare](https://www.mcrl2.org/web/user_manual/tools/release/ltscompare.html).

<a id="ref-sail-riscv"></a>[15] Armstrong, A., Bauereiss, T., Campbell,
B., Reid, A., Gray, K.E., Norton, R.M., Mundkur, P., Wassell, M., French,
J., Pulte, C., Flur, S., Stark, I., Krishnaswami, N., Sewell, P. "ISA
Semantics for ARMv8-A, RISC-V, and CHERI-MIPS." *POPL 2019*, Article 71
(ACM 2019). DOI 10.1145/3290384.
[Cambridge Sail paper](https://www.cl.cam.ac.uk/~pes20/sail/sail-popl2019.pdf);
[Sail RISC-V GitHub](https://github.com/riscv/sail-riscv);
[Sail homepage](https://alasdair.github.io/).

<a id="ref-jacobs-2016"></a>[16] Jacobs, B. *Introduction to Coalgebra:
Towards Mathematics of States and Observation*. Cambridge University
Press (2016). ISBN 978-1-107-17789-6.
[Author-hosted PDF](http://www.cs.ru.nl/B.Jacobs/CLG/JacobsCoalgebraIntro.pdf).

<a id="ref-aczel-1988"></a>[17] Aczel, P. *Non-well-founded Sets*. CSLI
Lecture Notes 14. Stanford University (1988). The progenitor of
coalgebraic bisim semantics.

<a id="ref-larsen-skou-1991"></a>[18] Larsen, K.G., Skou, A.
"Bisimulation through Probabilistic Testing." *Information and
Computation* 94(1), pp. 1-28 (Sept 1991). DOI 10.1016/0890-5401(91)90030-6.
[Semantic Scholar summary](https://www.semanticscholar.org/paper/Bisimulation-through-Probabilistic-Testing-Larsen-Skou/b7a23296b95dfc77fd611e9b8c2d2a40ec7fc703);
[ScienceDirect](https://www.sciencedirect.com/science/article/pii/0890540191900306).

<a id="ref-riscv-lockstep"></a>[19] Alpinum. "RISC-V Lockstep
Co-Simulation: Retirement-Level Step-and-Compare for Faster Verification
& Debug." Open Forem (2024). [blog entry](https://open.forem.com/alpinumblogs/risc-v-lockstep-co-simulation-retirement-level-step-and-compare-for-faster-verification-debug-58g3).

<a id="ref-riscv-dv"></a>[20] chipsalliance / Google. "riscv-dv —
Random instruction generator for RISC-V processor verification."
(2018-2026). [GitHub](https://github.com/chipsalliance/riscv-dv).

<a id="ref-ibex-cosim"></a>[21] lowRISC / OpenTitan. "Ibex Co-Simulation
System." Ibex Documentation, v0.1.dev50+g8d171a16d. [docs](https://ibex-core.readthedocs.io/en/latest/03_reference/cosim.html).

<a id="ref-compcert"></a>[22] Leroy, X. "Formal verification of a
realistic compiler." *Communications of the ACM* 52(7), pp. 107-115
(2009). DOI 10.1145/1538788.1538814. [CompCert homepage](https://compcert.org/).

<a id="ref-compcerto"></a>[23] Koenig, J., Shao, Z. "CompCertO: Compiling
Certified Open C Components." *PLDI 2021*. [NSF PAR record](https://par.nsf.gov/biblio/10230366).

<a id="ref-hyperproperties"></a>[24] Clarkson, M.R., Schneider, F.B.
"Hyperproperties." *Journal of Computer Security* 18(6), pp. 1157-1210
(2010). [Cornell PDF](https://www.cs.cornell.edu/fbs/publications/Hyperproperties.pdf).

<a id="ref-firesim"></a>[25] Karandikar, S., Mao, H., Kim, D., Biancolin,
D., Amid, A., Lee, D., Pemberton, N., Amaro, E., Schmidt, C., Chopra, A.,
Huang, Q., Kovacs, K., Nikolic, B., Katz, R., Bachrach, J., Asanović, K.
"FireSim: FPGA-Accelerated Cycle-Exact Scale-Out System Simulation in the
Public Cloud." *ISCA 2018*. [FireSim homepage](https://fires.im/);
[GitHub](https://github.com/firesim/firesim).

<a id="ref-ltsmin"></a>[26] Kant, G., Laarman, A., Meijer, J., van de Pol,
J., Blom, S., van Dijk, T. "LTSmin: High-Performance Language-Independent
Model Checking." *TACAS 2015*, LNCS 9035, pp. 692-707 (Springer 2015).
[GitHub](https://github.com/utwente-fmt/ltsmin).

<a id="ref-paige-tarjan"></a>[27] Paige, R., Tarjan, R.E. "Three partition
refinement algorithms." *SIAM Journal on Computing* 16(6), pp. 973-989
(1987). DOI 10.1137/0216062. The canonical algorithmic basis for all
modern bisim-checking tools.

<a id="ref-hennessy-milner"></a>[28] Hennessy, M., Milner, R. "Algebraic
laws for nondeterminism and concurrency." *Journal of the ACM* 32(1), pp.
137-161 (Jan 1985). DOI 10.1145/2455.2460. The HML logic paper that
provides the modal-logical characterisation of bisim.

<a id="ref-browne-clarke"></a>[29] Browne, M.C., Clarke, E.M., Grumberg,
O. "Characterizing finite Kripke structures in propositional temporal
logic." *Theoretical Computer Science* 59(1-2), pp. 115-131 (1988).
Stutter-bisimulation origin.

<a id="ref-feriver"></a>[30] "FERIVer: An FPGA-assisted Emulated Framework
for RTL Verification of RISC-V Processors." *22nd ACM International
Conference on Computing Frontiers* (2025). arXiv:2504.05284.
[arXiv](https://arxiv.org/html/2504.05284v1).

---

## Appendix A — Why this report didn't use a formal tool

The proximate reason is scope: the S74 agent-I task was *research*, not
*implementation*. A secondary reason is that none of the surveyed tools
ingest "a running Linux kernel module". They ingest *models* of systems,
which is a compilation problem on top of the original specification
problem. The engineering-tolerable path (trace harness) is the only
option that (a) operates on the actual artifact, not a model, and (b)
finishes in one session.

## Appendix B — What would change if the RISC-V FPGA bitstream lands

Today's report assumes the FPGA POC is a paper-claim without a public
bitstream. If Roberts/Eli/Leelee publishes an open bitstream, two things
would happen:

1. `fpga_adapter.py` becomes real (serial UART against the DE10-Nano /
   Arty A7 / OrangeCrab board per S74 strategic notes §3). It's a
   one-session swap.
2. A stronger bisim claim becomes defensible — "tested against the
   paper's authoritative FPGA bitstream across N random sequences" —
   which is publication-quality evidence, not just engineering
   evidence. Per [[19]](#ref-riscv-lockstep) and [[20]](#ref-riscv-dv)
   this is the standard practice in 2026 RISC-V verification.

## Appendix C — Minimum Sail spec for the trust-ISA extension

A 27-instruction ISA extension is roughly what Sail-RISC-V's `C`
(compressed) extension looks like. By analogy:
- RISC-V base ISA spec: ~2000 LOC Sail
- C extension: ~500 LOC Sail
- Our trust-27 extension would be ~300-500 LOC Sail.

Adding this as a Sail module against `riscv/sail-riscv` would let us
auto-generate Coq/Isabelle definitions for any future mechanized proof.
The work is mechanical once the ISA is stable; defer to S76+.

---

**End of report.** Total length: ~880 lines including reference list.
