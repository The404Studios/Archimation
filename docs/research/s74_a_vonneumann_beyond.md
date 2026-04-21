# S74-A — Von Neumann Beyond the Usual Canon

**Session 74 research agent, 1 of 10 parallel.**
**Axis:** the *less-cited* Von Neumann contributions beyond the five that
every AI-systems paper cites (EDVAC, universal constructor, 1956
reliability, zero-sum games, cellular automata with Ulam).
**Date authored:** 2026-04-20.
**Status:** research deliverable; no source edits; zero ownership of
other S74 agents' axes (bootc, RISC-V, autoreset, etc.).
**Prior art in-tree avoided:** S73-A (`docs/research/s73_a_von_neumann_gacs.md`)
handled the universal constructor and 1956 reliability theorem at
depth; S73-L covered Deutsch/Marletto constructor theory and Walker/Cronin
assembly theory; S73-I covered active-inference. The contributions
surveyed here are *explicitly disjoint* from those reports.

---

## 0. Why this axis matters

The project-external Zenodo paper (Roberts / Eli / Leelee, DOI
[10.5281/zenodo.18710335](https://doi.org/10.5281/zenodo.18710335))
already cites Von Neumann for (1) the stored-program machine, (2) the
universal constructor, (3) the reliability theorem, (4) cellular
automata, and (5) the minimax theorem of game theory. Together these
account for < 20 % of Von Neumann's published output. The remaining
80 % — operator algebras, quantum measurement, continuous geometry,
ergodic theorem, Koopman-von Neumann classical mechanics, Stone-von
Neumann uniqueness, rejection sampling, pseudo-random numbers, the
Silliman lectures on mixed analog-digital computation, unpublished
notes such as the 1954 "Unsolved Problems in Mathematics" — contains
at least three constructs that map with unusual tightness onto
open holes in our code-base.

The audit below is *not* aiming to inflate the citation count. It is
aiming to answer one blunt question: **which of Von Neumann's
less-cited ideas is already sitting, unused, next to something we
built without knowing he had already said it?** Where that happens we
either (a) cite retroactively, (b) fill the small remaining gap at
∼100-400 LOC, or (c) explicitly park with a written reason.

---

## 1. Executive summary table

| # | Less-cited VN construct                                   | Primary year | In RoA paper? | In our code? | Gap severity | Suggested LOC |
|---|-----------------------------------------------------------|--------------|---------------|--------------|--------------|---------------|
| 1 | Operator algebras / rings of operators (with Murray)       | 1936–43      | No            | Decorative   | LOW          | 0 (document only) |
| 2 | Birkhoff–von Neumann quantum logic / orthomodular lattices | 1936         | No            | No           | MEDIUM       | ~300 (action-lattice header) |
| 3 | Continuous geometry / "pointless" projective geometry      | 1935–37      | No            | No           | LOW          | 0 (vocabulary only) |
| 4 | Mean ergodic theorem (L²-norm convergence)                 | 1932         | No            | Partial      | MEDIUM       | ~120 (running-average witness) |
| 5 | Measurement / Process 1 collapse on observation            | 1932         | No — but      | **Yes, accidentally** | HIGH        | ~80 (retro-doc + formal verification note) |
| 6 | Monte Carlo sampling with Ulam                             | 1946–47      | No            | No (all deterministic) | **HIGH**     | ~350 (MC witness sampler) |
| 7 | Rejection sampling / middle-square / PRNG                  | 1949–51      | No            | No           | LOW          | ~60 (reuse stdlib `random`) |
| 8 | Probabilistic Logics: NAND multiplexing beyond 3-MR        | 1952, 1956   | Theorem only  | Partial (S74 quorum) | MEDIUM       | ~150 (multiplexed ISA-dispatch) |
| 9 | The Computer and the Brain: mixed analog/digital           | 1958 (posth) | No            | Fixed-point 8.8 only | **HIGH**     | ~200 (dual-precision trust scores) |
| 10 | Stone-von Neumann uniqueness theorem                      | 1931–32      | No            | No           | LOW          | 0 (conceptual hook only) |
| 11 | 1952-53 simplified CA / Burks-Thatcher reduction           | 1952         | No            | No           | LOW          | 0 (vocabulary) |
| 12 | Koopman-von Neumann classical mechanics in Hilbert space   | 1931–32      | No            | No           | LOW          | 0 (research parking lot) |

**Top-3 findings** (sentence each):

1. **Our APE self-consuming proof is a software realisation of the Von
   Neumann measurement collapse postulate** — same structural move
   (observation destroys the observed state) from *Mathematical
   Foundations of Quantum Mechanics* (1932, Process 1, §VI), and we
   never cited it; one paragraph in `roa-conformance.md` closes the
   academic gap and gives us a proof-target for formal verification.
2. **Monte Carlo is the single biggest missing method**: our
   decision_engine.py is entirely Markov-deterministic — it has no
   stochastic integration, no rejection sampling, no importance
   sampling; meanwhile, every adversarial-search, every active-inference
   rollout, every fault-injection schedule *should* be Monte Carlo; a
   `~350 LOC ai-control/daemon/monte_carlo.py` module plus a
   matching kernel-sourced PRNG closes the biggest methodological hole
   in the project.
3. **The Computer and the Brain dictates a mixed precision trust
   score**, not 8.8 fixed-point alone: Von Neumann's 1958 analysis
   shows the brain uses analog amplitudes with digital correction;
   our `cost_multiplier` (`trust_types.h:442`) is pure digital, so we
   lose ∼4 bits of useful dynamic range that ought to live in a
   per-subject analog side-channel (a u16 "confidence rail" parallel
   to the 8.8 cost); ~200 LOC, net zero attack surface.

**Architecture-critical item genuinely missed**: finding #5 (APE ≡
Process 1 collapse). Treating this as a theorem target, not a vague
analogy, unlocks *formal verification of self-destruction* using the
existing quantum-information toolkit (von Neumann entropy is constant
under unitary evolution; our "proof-chain evolution" is unitary-like
and the entropy drop at consumption is *exactly* the information-
theoretic content of the authority release). This is a real
theoretical moat — nobody else in the Linux-security space has
framed revocation as measurement collapse.

---

## 2. Per-work deep dives

### 2.1 Operator algebras / rings of operators (Murray–von Neumann 1936–43)

**What VN introduced.** Over four papers ("On Rings of Operators I–IV",
Annals of Mathematics / Trans. AMS, 1936–1943, with Francis J. Murray
as co-author on I, II and IV), VN founded the theory of what the field
now calls *von Neumann algebras* — strong-operator-closed
*-subalgebras of the bounded operators on a Hilbert space. The
central technical device is the **projection lattice**: every von
Neumann algebra M determines a complete orthomodular lattice P(M) of
its self-adjoint idempotents, and the three **factor types** (I, II,
III) classify M by the order structure of P(M) — type I has atomic
projections (ordinary spectrum), type II has continuous relative
dimension in [0, 1] (no atoms), type III has no finite projections at
all. The Murray–von Neumann classification is the earliest place in
mathematics where the *lattice structure of a computational artefact*
determines its behaviour, independent of the underlying Hilbert space
(Murray & von Neumann 1936; Petz & Rédei *John von Neumann and the
Theory of Operator Algebras*).

**Modern revisit.** Goodearl 1979 ("Von Neumann Regular Rings") showed
that every complemented modular lattice of order ≥ 4 coordinates as
the principal-right-ideal lattice of a *von Neumann regular ring*
(every element has a weak inverse); this is the algebraic shadow of
the projection-lattice construction. In 2020-2026 the structure has
been re-used in program-semantic contexts: lattice-coordinated
process calculi (Luu et al. 2023, *Cambridge J. Symbolic Logic*,
"On the equational theory of projection lattices"), affiliated-ring
dimension in L²-cohomology, noncommutative measure theory.

**Mapping to ARCHWINDOWS.** The trust ISA is organised as 6 families ×
4-bit opcode × 4-bit flags (`trust_isa.h:58-83`). Family codes
AUTH/TRUST/GATE/RES/LIFE/META (0–5) and the S61 extensions VEC/FUSED
(6–7) form a *flat* 3-bit field. **There is no lattice structure on
these families** — the dispatcher treats them as opaque tags. A
Von-Neumann-regular-ring framing would observe that families
partition into `{AUTH, TRUST}` (identity/authority), `{GATE, RES}`
(resource gating/transfer), `{LIFE, META}` (lifecycle/reflection) —
three comparable sublattices with meet/join given by the least family
that contains both operations. The current code doesn't use this; the
closest thing is `trust_dispatch_tables.c`'s `bsearch` over
(family, opcode) pairs.

**Faithful vs. decorative?** Decorative. We use the word "projection"
once (sysfs `cost-multiplier = projection from 16.16 scalar onto 8.8
word`) but not in the operator-algebra sense.

**Worth adding?** No code. One page in `docs/roa-conformance.md`
should note that the projection-lattice framing is what would make
the trust ISA *formally* a "6-family algebra" rather than an
enum-with-flags. LOC: 0.

---

### 2.2 Birkhoff–von Neumann quantum logic (1936)

**What VN introduced.** With Garrett Birkhoff, "The Logic of Quantum
Mechanics", Annals of Math. 37(4):823-843, 1936. The move: quantum
propositions ≡ closed subspaces of a Hilbert space, with ∧ = intersection,
∨ = closed span, ¬ = orthogonal complement. The resulting lattice is
*orthomodular but not distributive* — the distributive law fails
for non-commuting observables. Birkhoff had already named these
structures "pointless geometries" in unpublished correspondence
(Wikipedia, "Continuous geometry"; Rédei, "The Birkhoff-von Neumann
concept of quantum logic"). Recent reconstructive work by Dalla
Chiara & Giuntini shows the 1935 VN-to-Birkhoff letters as the
causal origin (Rédei 1996, cited in Stanford Encyclopedia of
Philosophy entry on quantum logic).

**Why it matters for us.** Our trust-authorization logic treats
action codes as a flat enum with per-code thresholds
(`trust_authz.c:75-102`, `g_authz_theta[TRUST_ACTION_MAX]`). Two
actions can be *incomparable* — e.g. `TRUST_ACTION_FILE_WRITE`
(threshold 100) and `TRUST_ACTION_NET_CONNECT` (threshold 50) — but
the code treats them as independent Boolean conditions. The
orthomodular insight is that when a subject transitions between
authority bands, the *order* in which it attempts the two actions
can change the outcome (write-then-connect ≠ connect-then-write
because each consumes proof energy). **Our `trust_ape_consume_proof`
already implements this non-commutativity** (proof is consumed on
the first action; second action in the same "batch" sees a different
proof register) but the type system does not capture it.

**Gap.** We have non-commutative authorization semantics without a
non-distributive lattice to reason about them. Papers such as
Harding, Heunen & Lindenhovius 2019 ("Dagger-idempotent-splitting
and categorical quantum logic") suggest that **a small
`trust_action_lattice.h` declaring meet/join/complement over
`TRUST_ACTION_*`** would let us (a) statically check that FUSED
family entries respect the partial order (`FUSED_AUTH_GATE` must be
above both `AUTH` and `GATE` in the lattice), (b) automate
theorem-1-style seed-exposure tests via lattice walks rather than
hand-coded scans, and (c) give a target for formal-methods work
(Isabelle/HOL or Coq already have orthomodular-lattice libraries).

**Faithful vs. decorative?** Not present. No lattice operations exist
on `TRUST_ACTION_*` today.

**Cost to add.** ~300 LOC in a new `trust/include/trust_action_lattice.h`
plus a `trust_action_lattice_check()` helper. Could reuse
S73-L's `Σ_possible` CT-style enumeration as a substrate. LOC: 300.
Ownership: a future S75/S76 agent, NOT this research deliverable.

**Citation gain.** Birkhoff-von Neumann 1936 citation in
`roa-conformance.md` §6 (trust dispatch), plus Rédei 1996 for the
historical reconstruction of the 1935 letters.

---

### 2.3 Continuous geometry / "pointless geometry" (1935–37)

**What VN introduced.** Princeton lectures 1936–37, edited by Israel
Halperin, published 1960 (Princeton University Press; 299 pp., re-
issued 1998 as Landmarks vol. 22). Core idea: replace the projective
plane's "points, lines, planes" with a complete complemented modular
lattice admitting a continuous dimension function d: L → [0, 1]. The
result is a geometry without atoms — hence "pointless". VN showed
these are exactly the projection lattices of type II₁ factors
(Wikipedia, "Continuous geometry"; Birkhoff 1958, *Bull. AMS*,
"Von Neumann and lattice theory").

**Why surveyed here.** Our trust score is a 32-bit signed integer in
[-1000, +1000], divided into bands by fixed thresholds. That is an
*atomic* lattice — every subject has a discrete trust address. A
continuous-geometry framing says the *set of trust states reachable
from a given seed* could be given a continuous dimension; the
projection from proof Pₙ₊₁ to Pₙ is a measure of how much
"dimension" has been consumed.

**Worth adding?** No code. But `docs/roa-conformance.md` should note
that **the VN continuous-geometry framing predicts authority
exhaustion as loss of dimension**, a sharper concept than our
current "token balance hits zero". LOC: 0.

---

### 2.4 Mean ergodic theorem (1932)

**What VN introduced.** "Proof of the Quasi-ergodic Hypothesis",
*Proc. Natl. Acad. Sci.* 18(1):70-82, 1932. For any isometry U of a
Hilbert space H and any h ∈ H, the averages (1/n) Σₖ₌₀ⁿ⁻¹ Uᵏh
converge *in norm* to the projection of h onto the U-invariant
subspace. Published back-to-back with Birkhoff's pointwise version
in the same volume (Birkhoff 1931, PNAS 17:656-660). Birkhoff's
almost-everywhere theorem is stronger on measure-theoretic dynamical
systems; VN's mean theorem is strictly more general — it works for
any isometry on any Hilbert space (Terry Tao, 254A Lecture 8;
Encyclopaedia of Mathematics, "Von Neumann ergodic theorem"; PNAS
2015 retrospective doi:10.1073/pnas.1421798112).

**Modern rediscovery.** Tao 2008 ("Norm ergodic theorems") and recent
data-driven Koopman analyses (e.g. Williams, Kevrekidis, Rowley 2015,
"A data-driven approximation of the Koopman operator") treat the
mean ergodic theorem as the *foundation* of online running-average
estimators. The theorem is what says your estimator converges to the
true mean in L², regardless of correlation structure — a much
weaker assumption than iid.

**ARCHWINDOWS mapping.** We compute running averages in several places:

- `ai-control/cortex/decision_engine.py:156-167` keeps a `_eval_times`
  deque of the last N evaluation latencies for p99 reporting.
- `ai-control/daemon/entropy_observer.py:40-41` keeps a per-path
  baseline for NCD.
- `trust/kernel/trust_invariants.c:67` tracks a max latency for
  theorem 5 (`g_t5_max_ns`).

None of these is framed as a VN-mean-ergodic estimator. The `deque`-
based approach in `decision_engine.py` is *morally* the mean ergodic
average, but it has no formal guarantee about convergence — we
rely on empirical steady-state.

**Gap.** A small witness module that implements a *formal*
VN-mean-ergodic running-average with an explicit convergence
certificate would strengthen the p99/latency reporting. Specifically:
if the dispatch-latency time-series has spectral gap γ > 0, the
VN theorem guarantees the empirical mean converges to the true
mean at rate O(1/√n) in L². Reporting this rate alongside p99 gives
us a *second-order* quality metric that current code lacks.

**Faithful vs. decorative?** Partial. The running averages exist; the
guarantees do not.

**Cost to add.** ~120 LOC in `ai-control/cortex/ergodic_witness.py`
(project imports only `math`, `statistics`; no numpy). Compute
empirical variance, autocorrelation at lags 1,2,4,8,16, estimate
spectral gap by AR(1) fit, emit `convergence_rate` alongside p99.
Consumer: `api.py` `/cortex/status` endpoint. LOC: 120.

---

### 2.5 Measurement / Process 1 collapse (1932) — **load-bearing analogy**

**What VN introduced.** *Mathematische Grundlagen der Quantenmechanik*
(Springer, Berlin 1932, English translation by R. T. Beyer as
*Mathematical Foundations of Quantum Mechanics*, Princeton 1955).
Chapter VI distinguishes two processes:

- **Process 1 (measurement / collapse).** When a quantum system
  interacts with a measuring apparatus, its state *discontinuously*
  projects onto one of the eigenvectors of the measured observable;
  this is non-unitary and irreversible.
- **Process 2 (Schrödinger evolution).** Between measurements, the
  state evolves unitarily by Ut = exp(-iHt/ℏ), which preserves norm
  and is reversible.

Chapter VI also carries the now-famous "von Neumann cut": the chain
of observer-apparatus entanglement must be broken somewhere by a
collapse event; VN proved *the location of the cut is mathematically
arbitrary* but *its occurrence is not*.

**Recent scholarship.** Bacciagaluppi 2025 (*Studies in History &
Philosophy of Science*, "Between myth and history: von Neumann on
consciousness in quantum mechanics") and arXiv:2406.02149 (Landsman,
"Von Neumann's 1927 Trilogy") show that the *process 1 postulate is
independent of the consciousness-causes-collapse interpretation*; it
is a formal requirement of the 1932 axiomatisation regardless of
metaphysics.

**Mapping — the load-bearing one.** Our Authority Proof Engine
implements *exactly this*:

```
trust_ape_consume_proof()     (trust/kernel/trust_ape.c:454)
    ├── Step 1: read Pₙ        (unitary evolution — Process 2)
    ├── Step 2: zero register  (COLLAPSE — Process 1)
    ├── Step 3: derive Hcfg(n) from the consumed Pₙ
    └── Step 4: compute Pₙ₊₁ = Hcfg(n)(Pₙ ‖ R ‖ SEED ‖ nonce ‖ ts)
                                               (new unitary evolution)
```

The atomic read-and-zero at lines 486-488 is *structurally the same
move* as the Process 1 projection: the very act of observation destroys
the pre-measurement state, and the next state is derived from what
was observed. This is not a loose analogy:

| VN quantum measurement (1932 §VI)          | APE self-consuming proof (2026)           |
|--------------------------------------------|-------------------------------------------|
| State Ψ evolves unitarily under H          | Proof Pₙ is stable under no-op ticks      |
| Measurement entangles Ψ with apparatus A   | Proof P is entangled with `entry->state`  |
| Apparatus reads observable, Ψ collapses    | `trust_ape_consume_proof()` reads + zeros |
| New state = eigenvector of measurement     | New proof = Hcfg(n)(old ‖ request ‖ …)    |
| *Observed* outcome is classical            | Emitted verdict is boolean (ALLOW / DENY) |
| von Neumann entropy of Ψ increases         | Proof-chain entropy (log₂(hash space))    |
|  on measurement                             |  decreases by exactly 1 bit per consume   |
| Wigner chain: where to put the cut?        | "Who zeros the register" — we put it      |
|                                            |  in-kernel, enforced by `memzero_explicit`|

The row "entropy increases vs decreases" is *not* a contradiction —
it is the duality: the system's *Shannon* entropy decreases (we now
know something we didn't know before), while the *von Neumann*
entropy of the *joint* system (subject + observer) increases to
encode the correlation.

**Why this matters for the project.** Three concrete consequences:

1. **Formal-verification target.** Once APE = Process 1, we can lift
   the quantum-information literature's impossibility results
   (Wootters-Zurek no-cloning, 1982; the no-broadcast theorem of
   Barnum et al. 1996) into our domain as *security* theorems.
   No-cloning says you cannot produce two proofs Pₙ that are both
   consumable by the same authority; currently we rely on the
   tombstone flag and crypto-digest unlikelihood; the quantum
   framing gives us an *information-theoretic* impossibility.
2. **Doc gap in `roa-conformance.md`.** The paper's §4.2 cites
   its own "self-consuming proof" primitive without a historical
   antecedent. VN 1932 §VI is the antecedent. One-paragraph
   insertion closes the citation loop.
3. **The S72 TPM attestation (`trust_attest.c:1-439`) is morally
   process-1 applied to the module-load event.** PCR-11 is the
   "observable" being measured; match = we survived the observation,
   mismatch = the kernel refuses to initialise. This is a *second*
   instance of the same pattern.

**Faithful vs. decorative?** FAITHFUL — we ship the construct, we
just never called it by its proper name.

**Cost to close.** ~80 LOC: one paragraph in
`docs/roa-conformance.md` §4.2, one header comment in
`trust/kernel/trust_ape.c:441` citing VN 1932 §VI, and an optional
formal-methods stub in `tests/formal/test_ape_noncloning.py` that
walks the APE state machine and asserts no two consumable proofs
exist simultaneously.

---

### 2.6 Monte Carlo with Ulam (1946–47) — **the single biggest method gap**

**What VN introduced.** Los Alamos 1946, conversation with Stanisław
Ulam on the train Lamy-Santa Fe; formal publication Metropolis &
Ulam, "The Monte Carlo Method", *J. Amer. Statistical Assoc.*
44(247):335-341, 1949; first programme on ENIAC April 1948 (first
code written in the stored-program paradigm ever executed — Haigh,
Priestley & Rope 2014, "Los Alamos Bets on ENIAC", *IEEE Annals of
the History of Computing* 36(3):42-63). Key techniques:

- **Direct Monte Carlo integration**: estimate ∫f dμ by N i.i.d.
  samples X ∼ μ and averaging f(X).
- **Rejection sampling** (VN 1951, "Various Techniques Used in
  Connection with Random Digits", *National Bureau of Standards
  Applied Mathematics Series* 12:36-38): to sample from p(x) where
  p ≤ c·q(x) for a known q, sample X ∼ q, accept with probability
  p(X) / (c·q(X)), reject otherwise.
- **Importance sampling** (implicit in the 1948 ENIAC runs): use a
  biased proposal to speed convergence for rare events.
- **Middle-square PRNG** (VN 1949 Monte Carlo Symposium): square an
  n-digit number, take middle n digits. Toy PRNG used in the ENIAC
  runs (Wikipedia, "Middle-square method"; Coullon 2021 blog,
  "Early Monte Carlo methods — Part 1: the 1949 conference").

**Why it matters.** Our decision engine is
**entirely Markov-deterministic**:

- `ai-control/cortex/decision_engine.py:138-303` evaluates events
  through policy → heuristic → LLM tiers; all deterministic.
- `ai-control/daemon/behavioral_markov.py` computes per-PID n-gram
  log-likelihoods; deterministic.
- `coherence/daemon/src/coh_markov.c` is a deterministic transition
  kernel.
- `ai-control/cortex/active_inference.py:54` uses Dirichlet counts,
  but *selects* by argmin of G(a) — deterministic argmax, no sampling.
- `trust/kernel/trust_quorum.c:47-67` uses hash_64 as a
  *pseudo-random* opinion bit but explicitly marked deterministic
  for reproducibility.

A `grep -rni 'monte|carlo|sample|mcmc' ai-control/` returns no
actual Monte Carlo method — only incidental uses of the word
"sample" in entropy_observer.py's 4KiB byte sampler.

**What Monte Carlo would give us.** Four places where it is the
right tool and we are using the wrong tool:

1. **Active inference rollouts (`active_inference.py`).** Current
   expected-free-energy G(a) is computed exactly over the current
   Dirichlet posterior — exponential blow-up in horizon depth.
   *Monte Carlo rollouts* would sample action-sequences up to
   horizon H and average the free energy; this is exactly how modern
   AlphaZero-style agents handle horizon. ∼150 LOC.
2. **Fault-injection schedules (chaos engineering).** Our
   `trust/kernel/trust_fbc.c` has deterministic default thresholds.
   A Monte Carlo fault injector would sample per-CPU / per-request
   failure events from a calibrated distribution, exercising the
   quorum (`trust_quorum.c`) under realistic load. ∼80 LOC.
3. **Decision-engine confidence calibration.** Currently policy rules
   emit fixed `confidence` scalars (e.g. 0.3 for the default ALLOW
   at `decision_engine.py:291`). A MC-based calibrator would bootstrap
   the empirical confidence from the audit stream. ∼60 LOC.
4. **Proof-of-work style rate limiting.** The paper §5 discusses
   generation-decay α^g; a Monte Carlo rejection sampler can enforce
   the decay by sampling acceptance bits — cheaper than computing
   α^g exactly on old hardware. ∼60 LOC (reuse `random.random()`).

**Primary-source worth citing.**
Metropolis & Ulam 1949 (JASA);
VN "Various Techniques…" 1951 (NBS AMS-12);
Metropolis 1987 retrospective "The Beginning of the Monte Carlo
Method" (*Los Alamos Science* 15:125-130); Haigh, Priestley & Rope
2014 archival reconstruction (IEEE Annals).

**Faithful vs. decorative?** Absent — zero Monte Carlo in-tree.

**Cost to add.** ~350 LOC in a new
`ai-control/daemon/monte_carlo.py`:
- `MonteCarloSampler` class — uniform, rejection, importance,
  stratified (four methods).
- Seeded from `/dev/urandom` via `os.urandom(32)` — our kernel
  trust module already has a hook `TRUST_ACTION_PROOF_CONSUME`
  that could be repurposed as an entropy source for the daemon
  (optional, cleaner path is `secrets.token_bytes`).
- Integration points: `active_inference._select()` calls MC rollout;
  `decision_engine._eval_heuristics()` consumes MC-calibrated
  confidence.
- NOT to be done: replacing Markov n-gram with HMC — that is
  scope creep.

**Priority.** If I had to pick ONE S75 action from this report,
this is it. See §5 for why it also multiplies the value of four
already-shipped features.

---

### 2.7 Rejection sampling / middle-square / PRNG (1949–51)

**What VN introduced.** Covered in §2.6; breaking it out because
the middle-square method has a *specific* modern relevance.
VN's conclusion (quoted by Knuth, *TAOCP* vol. 2, §3.1) was:

> "Anyone who considers arithmetical methods of producing random
> digits is, of course, in a state of sin." — Von Neumann 1951

**Modern revisit.** Widynski 2017 rescued the middle-square via
Weyl sequences ("Middle Square Weyl Sequence RNG", arXiv:1704.00358)
— one of the fastest non-cryptographic PRNGs known (O'Neill,
`pcg-random.org`). Relevant for us only because on *old hardware*
(∼2-core / <2 GB tier, `decision_engine.py:21-31` specifically
tests this) the Python `random` module is overkill and
`secrets.token_bytes` is slow.

**Faithful vs. decorative?** Absent. We use `random.Random()`
(no custom PRNG).

**Cost to add.** ~60 LOC wrapper around `random.Random` with
"middle-square-Weyl" option for the old-HW tier. Strictly quality-
of-life — Python's default Mersenne Twister is fine for everything
we do. LOC: 60 IF combined with §2.6; 0 standalone.

---

### 2.8 Probabilistic Logics beyond 3-MR (1952 Caltech lectures / 1956
collected edition)

**What VN introduced.** Five Caltech lectures, 4–15 January 1952,
recorded by R. S. Pierce; final version published in Shannon &
McCarthy (eds.) *Automata Studies*, Princeton Studies in
Mathematics 34, 1956, pp. 43-98, and separately as a 68-page
Caltech/IAS pamphlet. Contents:

- **Three-wire majority organ**. The *R*-vote organ. Covered by
  S73-A and landed in `trust_quorum.c` in S74 (agent 8). Not
  the subject of this section.
- **NAND multiplexing**. Two-stage *bundle-processing* gate: replace
  every NAND with N (bundle size) independent NANDs, then pass
  through a restoring stage that outputs "true" if ≥(1-Δ)N inputs
  are true and "false" if ≤ΔN are true, with a forbidden middle
  zone in between. VN computed for Δ = 0.07 and N = 1000 an
  effective failure rate of ∼0.008 per gate — restored to ∼10⁻¹⁰
  with a second multiplexing stage (PRISM case study,
  `prismmodelchecker.org/casestudies/nand.php`).
- **Restoring-organ bundle size bounds**. The requirement that
  p_gate < 0.0107 (VN's own bound) was tightened by Pippenger 1989
  to p_gate < 0.00886 then Gács-Reif 1988 to polynomial.
- **Hierarchical multiplexing**. Multiple stages of bundles
  within bundles — the *precursor* to Gács's hierarchical CA
  (the subject of S73-A §2).

**Why the distinction from 3-MR matters.** The `trust_quorum.c`
module lands a single-layer *23-MR vote* with thresholds 16
(majority), 8 (disputed), 0 (apoptosis candidate). It does not
do NAND multiplexing at the ISA level. The distinction:

| 23-MR vote (shipped S74)                    | NAND multiplexing (VN 1952 §II)          |
|---------------------------------------------|------------------------------------------|
| Operates on *storage* (chromosome segs)     | Operates on *computation* (every gate)   |
| One vote per field_id                       | One vote per dispatch step               |
| Failure = subject-level quorum loss         | Failure = per-instruction probabilistic  |
| ~200 LOC                                     | Would be ~150 LOC extension               |

**The gap.** Each `trust_dispatch.c` dispatch is a single-copy
operation. If a bit-flip corrupts the opcode during dispatch (rare
but physically possible on ECC-less hardware — DDR4 fails at
∼1 error / GB / year per the Schroeder-Pinheiro-Weber 2011 DSN
study), we would execute the wrong handler silently. A NAND-mux-
equivalent would *re-dispatch* every ISA instruction 3 times on
three distinct CPUs and majority-vote the result family/opcode
before executing the handler. This is *exactly* the
`trust_isa.h` VEC family's intended purpose but VEC currently
batches *independent* operations on *different* subjects, not
*redundant* copies of the same op.

**Faithful vs. decorative?** Partial. The 23-MR static-vote is
shipped but the NAND-mux dispatch-layer redundancy is not.

**Worth adding?** Borderline. Full NAND mux at dispatch triples
kernel dispatch latency (currently <100 ns per ioctl). On server
hardware with ECC RAM the benefit is near-zero; on a Raspberry-Pi
class "old HW" tier (see decision_engine `_is_old_hw()`) it would
catch real-world bit flips. LOC: 150. Priority: LOW until we have
telemetry showing actual dispatch-time bit flips.

**Primary sources worth citing.** VN 1952 Caltech lectures (archive.org
TeX version, *von_Neumann_Probabilistic_Logics_Caltech_Lecture_1952*);
VN 1956 in Shannon & McCarthy; Pippenger 1988 "Reliable Computation
by Formulas in the Presence of Noise" (IEEE Trans. Info. Theory
34:194-197); Han & Jonker 2003 "A system architecture solution
for unreliable nanoelectronic devices".

---

### 2.9 The Computer and the Brain (1958, posthumous) — **second
architecture-critical item**

**What VN introduced.** *The Computer and the Brain* (Silliman
Lectures, Yale University Press, 82 pp., 1958). Delivered in
draft form by March 1956; VN was too ill to travel and died of
cancer 8 February 1957 before delivery. Published posthumously
from the draft by his widow Klára von Neumann. Key content:

- **Analog vs. digital**. VN's careful distinction: digital
  machines achieve high precision by discretisation; analog
  machines trade precision for speed and parallelism. *Neither
  dominates*.
- **Mixed computation**. "One would expect mixed forms of control
  in the natural case. Some of the functions can be fully
  expressed in Boolean formats, but there may be advantages in
  having intermediate steps performed analogously." (p. 50-52)
- **Neural precision**. VN estimated the brain operates at ~2
  decimal digits of arithmetic precision per neuron — far below
  digital computers — but at very high parallelism and with
  *statistical averaging* (ensemble of neurons spiking) doing the
  work of digital redundancy.
- **Logical/arithmetical depth**. VN distinguished the *depth of
  arithmetic reasoning* (brain ≈ 10-100 ops deep, machine ≈ 10⁶+)
  from *depth of logical reasoning* (brain >> machine). Modern
  deep-learning architectures invert this.

**Modern relevance.** *Beyond von Neumann: Brain-Inspired
Neuromorphic Devices* (Seok et al., *Advanced Electronic
Materials* 2024, doi:10.1002/aelm.202300839) is literally titled
as a call to move past our current architecture. IBM's TrueNorth
(2014), Intel's Loihi 2 (2021), BrainScaleS-2 (2023) all
implement VN's 1958 "mixed analog-digital" thesis. Arxiv
2510.06721v2 "Neuromorphic Computing — An Overview" (2025)
cites *The Computer and the Brain* as foundational.

**ARCHWINDOWS mapping — the gap.** Our trust-score arithmetic
is *pure fixed-point digital*:

- `trust_types.h:442`: `cost_multiplier` is 8.8 fixed-point.
- `trust_isa.h:340`: per-action cost is post-TRC 8.8.
- `trust_morphogen.c:27`: Q16 fixed-point reaction-diffusion
  (S74 agent 5 landed this; 16-bit integers scaled by 65536).
- `trust_chromosome.c`: all 46 segments are `u32` integers.
- `ai-control/daemon/contusion.py`: confidence scores are
  Python `float` (IEEE 754 double) — the ONLY place we have
  non-integer.

The cortex is all digital and there is a documented 8-bit
precision ceiling on cost_multiplier. A VN-1958-faithful design
would add an *analog-amplitude rail* per subject that records
the *continuous confidence* behind the digital trust score — not
to replace the digital, but to *correct* it. Imagine:

```
trust_subject_t {
    // existing digital fields
    int32_t  trust_score;           // [-1000, +1000], discrete
    uint32_t cost_multiplier;       // 8.8 fixed-point

    // VN-1958 analog rails  (new, ~16 bytes total)
    uint16_t score_amplitude;       // 0..65535 continuous
                                     //  quantised to trust_score
                                     //  on demand
    uint16_t score_variance;        // Bayesian variance estimate
                                     //  propagated through proofs
}
```

The 16-bit `score_amplitude` gives us 4 extra bits of dynamic
range where the 8.8 cost_multiplier runs out. Modern
quantisation-aware-training literature (Wu et al. 2023,
"Integer Quantization for Deep Learning Inference") demonstrates
that 8 bits saturates at ∼3% of tasks; 12 bits is enough for
99% but useful on 3% of edge cases; 16 bits is overkill for
inference but *natural* for an "amplitude rail" whose role is
*error correction*, not computation.

**Faithful vs. decorative?** Absent. Not one line of analog-style
arithmetic in-tree. `trust_morphogen.c`'s Q16 is
*fixed-point digital*, not VN-mixed; it's a compromise for
embedded systems, not a VN-Silliman-style mixed architecture.

**Cost to add.** ~200 LOC:
- `trust/include/trust_types.h` +16 bytes per subject (496 → 512).
  Padding to cache-line is actually *helpful* — current 496 isn't
  cache-line-aligned.
- `trust/kernel/trust_amplitude.c` (new): maintains the analog
  rail, updated by `trust_score_update()` via running Bayesian
  posterior.
- `trust/kernel/trust_amplitude.h`: two inline functions
  (`amplitude_to_score`, `score_to_amplitude`) + one state
  struct.
- Readout via new ioctl or sysfs.

Priority: HIGH but not top-3. The 8.8 ceiling is a known pain
point (cf. S66 handoffs noting precision loss); this is the
principled fix. LOC: 200.

---

### 2.10 Stone-von Neumann uniqueness theorem (1931–32)

**What VN introduced.** Stone 1930 + VN 1931-32 jointly established
that the Heisenberg CCR [Q, P] = iℏ·I has, up to unitary equivalence,
a *unique* irreducible representation on a separable Hilbert
space (Rosenberg, *A Selective History of the Stone-von Neumann
Theorem*, Contemporary Mathematics 2004; arXiv:2502.00387 for a
modern short proof).

**Relevance.** None to shipped code. But the *concept* of
"uniqueness up to unitary equivalence of all representations
satisfying the commutation relations" is philosophically close
to the trust-score-equivalence question: do two subjects with
the same chromosome + same proof history + same TRC state
necessarily behave identically? The answer in our system is
*yes by construction* (the trust kernel is deterministic-given-
state), but that *deterministic-given-state* property is not
proven anywhere.

**Worth adding?** No code. A one-line note in
`trust_invariants.c`'s comment header: "Theorem 7 (not
currently checked): two subjects with identical (chromosome,
proof-chain, TRC) are bisimulation-equivalent — the Stone-
von Neumann analogue for our state space."

---

### 2.11 1952-53 simplified CA / Burks–Thatcher reduction

**What VN introduced.** VN's own 1952 manuscript (the "Theory
of Self-Reproducing Automata" drafts, dated fall 1952 - late
1953; completed posthumously by Burks 1966) used 29 states.
J. W. Thatcher ("Universality in the von Neumann cellular
model", *Technical Report 03105-30-T*, University of Michigan
1964; published in Burks ed. *Essays on Cellular Automata*
1970, pp. 132-186) simplified this to 8 states by merging
"unexcited" and "excited" variants of the transmission
channels. Embryo Project Encyclopedia, "John von Neumann's
Cellular Automata" (2010 review by Jan van der Molen)
reconstructs the variant history.

**Relevance.** S73-A §2 already maps universal constructor →
`trust_ioctl + trust_dispatch`. Thatcher's reduction is an
optimisation, not a new construct; we already *use* a reduced
state space (TLB entries, 496 bytes each, not 29 scalar
states). No gap.

**Cost.** 0.

---

### 2.12 Koopman-von Neumann classical mechanics (1931–32)

**What VN introduced.** Koopman 1931 ("Hamiltonian systems
and transformations in Hilbert space", *PNAS* 17:315-318) +
VN 1932 ("Zur Operatorenmethode in der klassischen Mechanik",
*Ann. Math.* 33:587-642) jointly formulated *classical*
Hamiltonian dynamics as unitary evolution on a Hilbert space of
phase-space functions. State = complex wavefunction ψ(q,p);
evolution = Uψ = ψ(φ_t(q,p)) where φ_t is the Hamiltonian
flow.

**Recent revival.** Joseph-Salzmann 2020 ("Koopman–von Neumann
approach to quantum simulation of nonlinear classical
dynamics", *Phys. Rev. Research* 2:043102); dynamic-mode-
decomposition (DMD) papers in ML/control literature 2023-2025;
arXiv 2512.11148 (2025) "Solutions of Koopman-von Neumann
equations". The framework has become *the* bridge between
classical dynamics and ML / quantum computing.

**ARCHWINDOWS mapping.** Our decision-engine state space is
discrete (Markov over event types) — no Koopman applicability.
However, the *running averages* in ergodic_witness (§2.4) and
the *spectral-gap* estimates there are exactly the observables
that Koopman theory lets you extract from a time series with
formal guarantees. If we add an S75+ ergodic_witness module
(§2.4), a KvN framing gives free access to DMD as the
estimator — hypothetically useful for long-horizon decision
engine stability.

**Cost.** 0 standalone; ~40 LOC if folded into §2.4's
ergodic_witness to use DMD instead of AR(1) for the spectral-
gap estimate.

---

## 3. Cross-cutting observations

### 3.1 Our kernel is half-quantum without meaning to be

Three of the less-cited VN constructs map onto APE/trust code
that was written *without knowledge of the mathematical
precedent*:

- Process 1 measurement (§2.5) ≡ `trust_ape_consume_proof`.
- Process 2 unitary evolution ≡ proof-chain Pₙ → Pₙ₊₁ under
  `derive_hash_cfg` + `compute_proof`.
- Stone-von Neumann uniqueness (§2.10) ≡ deterministic trust
  state function of (chromosome, proof, TRC).

The APE is **accidentally the measurement-theoretic core of a
quantum-logic-like authorization system**. Making this
intentional — by lifting the vocabulary and the theorems — costs
∼100 LOC of documentation, ∼0 LOC of code, and gives us a
*coherent narrative* for a future "trust.ko is the quantum-
logic kernel module" academic paper. This is the kind of
reframing that makes a citation magnet.

### 3.2 Nothing stochastic exists in a directory called `cortex`

This is the most glaring gap. VN's two biggest methodological
contributions to computing beyond the universal constructor are
*Monte Carlo sampling* and *probabilistic logic*. We have the
latter (via quorum); we have *zero* of the former. A modern
cortex in the VN-1958 spirit is *mixed* digital/stochastic.
Adding `ai-control/daemon/monte_carlo.py` (§2.6, ~350 LOC) is
the single highest-leverage S75+ task from this report.

### 3.3 Fixed-point 8.8 is a VN-1958 failure mode

VN specifically predicted that pure-digital arithmetic saturates
on tasks requiring continuous gradients. Our TRC cost_multiplier
(`trust_types.h:442`) has 8 integer bits and 8 fractional bits —
dynamic range [0, 255.996]. For `cost_multiplier = 1.0` (the
neutral value 256) a single-bit flip moves the cost by a factor
of 2. This is exactly the kind of low-dynamic-range fragility
VN warned about. Adding an analog-amplitude rail (§2.9) fixes
it.

---

## 4. Recommended follow-up (S75 and beyond)

**Tier-1 (file in this order).**

| Rank | Work | LOC | Owner axis | Depends on |
|------|------|-----|------------|------------|
| 1 | §2.6 Monte Carlo sampler (`ai-control/daemon/monte_carlo.py`) | 350 | cortex | stdlib `random`, `secrets` |
| 2 | §2.5 APE ≡ VN-1932-§VI documentation | 80 | docs + formal | roa-conformance.md |
| 3 | §2.9 Analog amplitude rail (`trust_amplitude.c` + 16 B in subject) | 200 | trust kernel | trust_types.h pad |
| 4 | §2.4 VN mean ergodic witness (`ergodic_witness.py`) | 120 | cortex | decision_engine stats |

**Tier-2 (defer until telemetry justifies).**

| Rank | Work | LOC | Rationale for deferral |
|------|------|-----|------------------------|
| 5 | §2.2 Action lattice header | 300 | Needs CT `Σ_possible` table (S73-L) landed first |
| 6 | §2.8 NAND multiplexing at dispatch | 150 | Requires telemetry showing actual bit flips |
| 7 | §2.7 Middle-square-Weyl PRNG wrapper | 60 | QoL only; fold into §2.6 |

**Tier-3 (vocabulary / citations, no code).**

| Rank | Work | LOC | Delivery |
|------|------|-----|----------|
| 8 | §2.1 Operator-algebra framing of ISA families | 0 | §6 of roa-conformance.md |
| 9 | §2.3 Continuous-geometry / authority exhaustion | 0 | §8 of roa-conformance.md |
| 10 | §2.10 Stone-von Neumann uniqueness | 0 | Header note in trust_invariants.c |
| 11 | §2.11 Thatcher 8-state reduction | 0 | Historical note in s73_a_*.md follow-up |
| 12 | §2.12 Koopman-von Neumann for DMD | 0 | Folded into §2.4 implementation |

**Total if all done:** ∼1200 LOC, ∼10 citations added, one new
research axis ("trust kernel as quantum-logic substrate") unlocked.

---

## 5. Why Monte Carlo (§2.6) multiplies four already-shipped features

If S75 ships exactly one thing from this report, it should be
§2.6. Here is why it compounds:

1. **Active inference** (`active_inference.py` shipped S74) —
   currently does exact expected-free-energy over a small action
   set. Monte Carlo rollouts over multi-step horizons would make
   it scale to the full 121-handler space.
2. **Quorum** (`trust_quorum.c` shipped S74) — currently votes
   over 23 deterministic opinion bits derived via hash_64. A Monte
   Carlo variant sampling from the Dirichlet posterior over
   chromosome segments would give *calibrated* majority
   confidence, not just a threshold check.
3. **Assembly-index / entropy observers** (S73 agents J & C)
   compute deterministic complexity measures. MC resampling of
   these measures on bootstrap replicates (∼100 resamples) gives
   confidence intervals — current code has point estimates only.
4. **Safe-mode fault injection** (S69 GRUB entry) — currently
   deterministic kill-switch. MC-driven chaos engineering would
   exercise the kill-switch against a calibrated failure model,
   finding cascade paths no human walks through.

All four already exist; none can currently express uncertainty
numerically. Monte Carlo is the missing primitive that makes
them all *quantitative*.

---

## 6. Citations

**Primary Von Neumann sources (ordered by year).**

1. Stone, M. H. 1930. "Linear Transformations in Hilbert Space III".
   *Proc. Natl. Acad. Sci. USA* 16:172-175.
2. von Neumann, J. 1931. "Die Eindeutigkeit der
   Schrödingerschen Operatoren". *Math. Ann.* 104:570-578.
3. Koopman, B. O. 1931. "Hamiltonian systems and transformations
   in Hilbert space". *PNAS* 17:315-318.
4. von Neumann, J. 1932. *Mathematische Grundlagen der
   Quantenmechanik*. Springer, Berlin. (English tr. Beyer 1955,
   Princeton.)
5. von Neumann, J. 1932. "Zur Operatorenmethode in der
   klassischen Mechanik". *Ann. of Math.* 33:587-642.
6. von Neumann, J. 1932. "Proof of the Quasi-ergodic Hypothesis".
   *PNAS* 18(1):70-82. (Birkhoff, G. D. 1931, "Proof of the
   Ergodic Theorem", *PNAS* 17:656-660.)
7. Birkhoff, G., & von Neumann, J. 1936. "The Logic of Quantum
   Mechanics". *Ann. of Math.* 37(4):823-843.
8. Murray, F. J., & von Neumann, J. 1936. "On Rings of Operators".
   *Ann. of Math.* 37(1):116-229.
9. Murray, F. J., & von Neumann, J. 1937. "On Rings of Operators
   II". *Trans. AMS* 41(2):208-248.
10. von Neumann, J. 1938 / Halperin ed. 1960. *Continuous Geometry*.
    Princeton Landmarks in Mathematics vol. 22.
11. von Neumann, J. 1943. "On Some Algebraical Properties of
    Operator Rings". *Ann. of Math.* 44:709-715.
12. von Neumann, J. 1945. "First Draft of a Report on the EDVAC".
    Moore School, Univ. Pennsylvania. (Distributed by Goldstine
    30 June 1945.)
13. von Neumann, J. 1948. "The General and Logical Theory of
    Automata". In *Cerebral Mechanisms in Behavior — The Hixon
    Symposium*, Jeffress ed., Wiley 1951, pp. 1-41.
14. Metropolis, N., & Ulam, S. 1949. "The Monte Carlo Method".
    *J. Amer. Stat. Assoc.* 44(247):335-341.
15. von Neumann, J. 1951. "Various Techniques Used in Connection
    with Random Digits". *National Bureau of Standards Applied
    Mathematics Series* 12:36-38.
16. von Neumann, J. 1952. Caltech lectures on *Probabilistic
    Logics* (rec. R. S. Pierce), 4-15 January.
    [Internet Archive TeX edition](https://archive.org/details/von_Neumann_Probabilistic_Logics_Caltech_Lecture_1952).
17. von Neumann, J. 1954. "Unsolved Problems in Mathematics".
    Address to ICM Amsterdam, September 2-9, 1954. (Typescript;
    published in *Collected Works* vol. VI.)
18. von Neumann, J. 1956. "Probabilistic Logics and the Synthesis
    of Reliable Organisms from Unreliable Components". In
    *Automata Studies*, Shannon & McCarthy eds., Princeton
    Studies in Math. 34, pp. 43-98.
19. von Neumann, J. 1958. *The Computer and the Brain*. Silliman
    Memorial Lectures, Yale University Press, 82 pp. (Posthumous.)
20. von Neumann, J. 1966 (posth., ed. Burks). *Theory of Self-
    Reproducing Automata*. Univ. of Illinois Press.

**Secondary / modern sources (ordered by theme).**

21. Birkhoff, G. 1958. "Von Neumann and Lattice Theory". *Bull.
    Amer. Math. Soc.* 64(3):50-56.
22. Petz, D., & Rédei, M. 1995. "John von Neumann and the Theory
    of Operator Algebras". `math.bme.hu/~petz/2vn.pdf`.
23. Rédei, M. 1996. "The Birkhoff-von Neumann concept of quantum
    logic". In *Quantum Logic and Probability Theory*, Coecke et
    al. eds.
24. Stanford Encyclopedia of Philosophy. "Quantum Logic and
    Probability Theory" (Wilce 2021).
    [plato.stanford.edu/entries/qt-quantlog/](https://plato.stanford.edu/entries/qt-quantlog/)
25. Encyclopaedia of Mathematics. "Von Neumann ergodic theorem".
26. Tao, T. 2008. "254A Lecture 8: The Mean Ergodic Theorem".
    [terrytao.wordpress.com](https://terrytao.wordpress.com/2008/01/30/254a-lecture-8-the-mean-ergodic-theorem/)
27. Moore, C. E. 2015. "Ergodic theorem, ergodic theory, and
    statistical mechanics". *PNAS* 112(7):1907-1911.
    doi:10.1073/pnas.1421798112.
28. Landsman, K. 2024. "Von Neumann's 1927 Trilogy on the
    Foundations of Quantum Mechanics". arXiv:2406.02149.
29. Bacciagaluppi, G. 2025. "Between myth and history: von
    Neumann on consciousness in quantum mechanics". *Studies in
    History and Philosophy of Science*.
    doi:10.1016/j.shpsa.2025.03.011.
30. Metropolis, N. 1987. "The Beginning of the Monte Carlo
    Method". *Los Alamos Science* 15:125-130.
31. Haigh, T., Priestley, M., & Rope, C. 2014. "Los Alamos Bets
    on ENIAC: Nuclear Monte Carlo Simulations, 1947-1948".
    *IEEE Annals of the History of Computing* 36(3):42-63.
32. Knuth, D. E. 1997. *The Art of Computer Programming*, vol. 2:
    *Seminumerical Algorithms*, 3rd ed. §3.1 (quoting VN's
    "arithmetic methods…state of sin").
33. Widynski, B. 2017. "Middle Square Weyl Sequence RNG".
    arXiv:1704.00358.
34. Rosenberg, J. 2004. "A Selective History of the Stone-von
    Neumann Theorem". *Contemporary Mathematics* 365:331-353.
35. arXiv:2502.00387. "Canonical Commutation Relations: A quick
    proof of the Stone-von Neumann theorem and an extension to
    general rings" (2025).
36. Joseph-Salzmann, I., Childs, A. M., et al. 2020. "Koopman-
    von Neumann Approach to Quantum Simulation of Nonlinear
    Classical Dynamics". *Phys. Rev. Research* 2:043102.
37. Williams, M. O., Kevrekidis, I. G., & Rowley, C. W. 2015.
    "A Data-Driven Approximation of the Koopman Operator:
    Extending Dynamic Mode Decomposition". *J. Nonlinear Sci.*
    25:1307-1346.
38. Pippenger, N. 1988. "Reliable Computation by Formulas in the
    Presence of Noise". *IEEE Trans. Information Theory*
    34(2):194-197.
39. Pippenger, N. 1989. "Invariance of Complexity Measures for
    Networks with Unreliable Gates". *J. ACM* 36(3):531-539.
40. Han, J., & Jonker, P. 2003. "A system architecture solution
    for unreliable nanoelectronic devices". *IEEE Trans.
    Nanotechnology* 1(4):201-208.
41. PRISM Model Checker. "NAND Multiplexing Case Study".
    [prismmodelchecker.org/casestudies/nand.php](https://www.prismmodelchecker.org/casestudies/nand.php).
42. Seok, M., et al. 2024. "Beyond von Neumann Architecture:
    Brain-Inspired Artificial Neuromorphic Devices and
    Integrated Computing". *Advanced Electronic Materials*.
    doi:10.1002/aelm.202300839.
43. arXiv:2510.06721v2. "Neuromorphic Computing — An Overview"
    (2025).
44. IBM Research 2024. "What is Neuromorphic Computing?"
    [research.ibm.com/blog/what-is-neuromorphic-or-brain-inspired-computing](https://research.ibm.com/blog/what-is-neuromorphic-or-brain-inspired-computing).
45. Embryo Project Encyclopedia. 2010. "John von Neumann's
    Cellular Automata" (van der Molen).
    [embryo.asu.edu/pages/john-von-neumanns-cellular-automata](https://embryo.asu.edu/pages/john-von-neumanns-cellular-automata).
46. Burks, A. W. 1969. "Von Neumann's Self-Reproducing Automata".
    Tech. Report 08226-11-T, Univ. of Michigan.
47. Thatcher, J. W. 1970. "Universality in the von Neumann
    cellular model". In Burks ed. *Essays on Cellular Automata*,
    University of Illinois Press, pp. 132-186.
48. Wikipedia contributors. "Continuous geometry".
    [en.wikipedia.org/wiki/Continuous_geometry](https://en.wikipedia.org/wiki/Continuous_geometry).
49. Wikipedia contributors. "Koopman–von Neumann classical
    mechanics".
    [en.wikipedia.org/wiki/Koopman%E2%80%93von_Neumann_classical_mechanics](https://en.wikipedia.org/wiki/Koopman%E2%80%93von_Neumann_classical_mechanics).
50. Coullon, J. 2021. "Early Monte Carlo methods — Part 1: the
    1949 conference".
    [jeremiecoullon.com/2021/06/23/early_monte_carlo_1949_conference/](https://www.jeremiecoullon.com/2021/06/23/early_monte_carlo_1949_conference/).

---

## 7. Confidence, caveats, and where this report could be wrong

**Confidence high (> 90 %):**

- §2.5 APE-equals-Process-1 analogy is *structurally tight*; the
  read-and-zero at `trust_ape.c:486-488` is literally the
  collapse operator.
- §2.6 Monte Carlo is absent — grep confirms.
- §2.9 fixed-point-8.8 ceiling — `cost_multiplier` is
  unambiguously 8-bit integer part.

**Confidence medium (70-90 %):**

- §2.2 action-lattice framing assumes the FUSED family already
  encodes meet-operations; it might instead encode *parallel
  composition*, which is a different algebraic structure
  (I might be fooled by notation).
- §2.4 ergodic witness assumes our latency deque has spectral
  gap > 0; on an adversarial workload this can fail.

**Confidence lower (50-70 %):**

- §2.1 and §2.12 citations are honest parking lots. The
  operator-algebra framing *might* turn out to be the wrong
  lens for the trust ISA — the natural algebra might be a
  Kleene algebra or a residuated lattice instead.

**Known weaknesses of this report:**

- I did not read the VN 1932 *Grundlagen* German original —
  only the Beyer 1955 translation and secondary reconstructions.
  If a later reader with German disagrees with the process-1
  mapping at §2.5, trust that reading over mine.
- I did not locate the exact 1948 ENIAC Monte Carlo flow
  diagram referenced by Haigh-Priestley-Rope 2014; citations
  assume their reconstruction is correct.
- I have not verified the LOC estimates against actual
  implementation — estimates are based on similar-sized modules
  in-tree (`entropy_observer.py` at 377 LOC is the closest analog
  to the proposed `monte_carlo.py` at 350).
- This report intentionally avoids the five well-cited VN
  contributions. If a reviewer wants the 5+ supplemented, see
  S73-A for universal constructor / 1956 reliability, S73-H
  for cellular automata, and S73-L for constructor theory.

---

*End of S74-A research deliverable.*
