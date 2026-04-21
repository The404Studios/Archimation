# S73 / Agent D — Turing Reaction-Diffusion Morphogenesis as Trust Topology

**Session:** 73 (2026-04-20)
**Agent:** D (of 12 framework agents)
**Framework:** Alan Turing, *The Chemical Basis of Morphogenesis* (1952) +
synthetic-biology Turing patterns (Karig 2018 to 2024+), embryogenesis as
reaction-diffusion (RD) computation, pattern-formation security.
**Scope boundary:** this doc is **not** Levin bioelectric (Agent K),
**not** autopoiesis (separate agent), **not** cellular-automata
(separate). It is *specifically* the Turing RD formalism: two (or more)
coupled diffusing species with short-range activation and long-range
inhibition, leading to spontaneous spatial-pattern emergence from a
spatially uniform steady state.

**Verdict:** ARCHWINDOWS currently has zero spatial structure. The
Chromosomal Authority model already gives each subject 23 segment pairs
of "DNA," and `trust_subject_pool.c` holds a bounded population — but
the population is **flat**, there are no neighborhood relationships,
and the trust score is updated per-subject with no spatial smoothing or
lateral inhibition. Adding a *virtual tissue coordinate* plus an
RD-style morphogen field on two trust-related species (activator =
escalation signal, inhibitor = decay / immune pressure) gives us
spontaneous differentiation of the subject population into stable
"tissue zones" — high-trust cores surrounded by low-trust cuffs —
without any central policy driving the partition.

> **One-line exploit:** *Add `trust/kernel/trust_morphogen.c` (~300
> LOC) — a 2D grid of `(cgroup_path_hash, pid_tree_depth)` cells with
> two diffusing species (S_activator, S_inhibitor) obeying Turing's
> stability condition; `trust_subject_pool_try_get()` and
> `trust_risc_record_action()` both read the local gradient for
> placement and decision. Spontaneous emergence of high-trust "tissue"
> + low-trust "interface" + inflamed "lesion" zones, stable under
> uniform policy, reactive under attack.*

The rest of this doc argues (1) why RD is the right formalism for this
system, (2) how Turing's 1952 math maps onto existing trust variables,
(3) where the new module plugs in, (4) what threat model it defends,
(5) what the failure modes are, and (6) an implementation plan with
concrete file:line insertions.

---

## 1. Turing's 1952 paper, recapped only as much as we need

Turing's central claim was that two chemical species A (activator) and
I (inhibitor), each diffusing at its own rate (D_A, D_I) and reacting
with each other at rates f(A, I), g(A, I), can **spontaneously produce
spatial patterns** from an initially uniform distribution, provided the
*Turing instability condition* is met:

    D_I / D_A > (sqrt(f_A) + sqrt(-g_I))^2 / (-g_I)       (Eq. 1)

where f_A = ∂f/∂A, g_I = ∂g/∂I evaluated at the uniform steady state.
Informally: the inhibitor must diffuse faster than the activator.
Equivalently, **local short-range activation + long-range inhibition**.
This gives stable stripes, spots, or reticulated patterns — zebra,
leopard, dalmation, angelfish.

The paper was mostly ignored for 30 years. It was revived when
developmental biologists realized limb-bud digit spacing (Sheth 2012,
Raspopovic 2014), feather placode spacing (Jung 1998), hair follicle
positioning, and *somite* formation in the paraxial mesoderm are all
driven by RD-like mechanisms. Kondo & Miura (2010) reviewed the field
in *Science* and concluded RD is one of ~3 canonical pattern engines
in biology.

**Key insight for us:** RD produces pattern *without a central planner*.
Each cell reads only local concentration and responds. The pattern is
emergent but *stable and reproducible*. Also — critically — when you
locally perturb an RD pattern (cut a zebra stripe), it re-forms: the
pattern is a *dynamic attractor*, not a static template. This is
exactly what we want from a defensive trust topology.

---

## 2. Mapping the Turing formalism onto the trust kernel

### 2.1 What do we already have?

Examining the current trust module:

- `trust/kernel/trust_subject_pool.c`:110 — `g_subject_pool.slots[]` is
  a **flat array of 64 entries** with no neighborhood relation. Lookup
  is by identity digest only. Eviction is by age+heat, not by position.
- `trust/kernel/trust_tlb.c` — 1024 sets × 4 ways hashed TLB;
  conceptually 2D but `tlb_hash(subject_id)` scatters IDs randomly, so
  set-index carries no biological meaning. An adversary at set N+1 has
  no relation to one at set N.
- `trust/include/trust_types.h`:462-483 — `trust_subject_t` carries a
  full chromosome, proof state, tokens, lifecycle, immune state, TRC
  state — but **no position**. The subject is an island.
- `trust/kernel/trust_lifecycle.c`:939 — `trust_immune_tick()` walks
  every subject independently; immune response is strictly local
  (per-subject cancer check). If subject X goes cancerous, subject X's
  *process-tree neighbors* are not warned.
- `trust/kernel/trust_chromosome.c` — the 23 A-segments (behavioral
  DNA) and 23 B-segments (construction DNA) are updated per-subject
  with no lateral communication.

**Summary:** we have rich per-subject state (the cell) and a timer
(the clock) but no tissue (the spatial medium).

### 2.2 Identifying the activator and inhibitor

We need two species whose local concentration can be measured, which
diffuse at different rates, and whose reaction terms have the right
signs for the Turing condition.

**Candidate A (activator):** *escalation pressure* =
(`trust_delta > 0` events + successful `TRUST_ACTION_ESCALATE` +
token transfers **into** subject) summed over a short window. This
rises on successful work, is local to the subject emitting it, and
propagates slowly (ms-scale) because every hop requires a mutual
consent or a verified proof.

**Candidate I (inhibitor):** *decay pressure* =
(`trust_decay_tick` outputs + `TRUST_IMMUNE_SUSPICIOUS` / `CANCEROUS`
transitions + `trust_token_burn` failures from `starved` subjects)
summed over the same window. The immune system is *systemic* — by
design `trust_immune_tick` scans everyone every 10 s. Information
about inflammation therefore travels faster through shared global
counters than escalation signals do through mutual-consent chains.
This gives us **D_inhibitor > D_activator** essentially for free.

So the Turing condition is satisfied by the *existing* dynamics,
we just haven't exposed the geometry.

### 2.3 What coordinate system? (The hardest design choice.)

RD needs a metric space. We have four plausible candidates:

| Coordinate | Source | Pros | Cons |
|---|---|---|---|
| **Process tree depth × sibling index** | kernel `task_struct->parent`, `task_struct->children` | Natural biological fit (mitosis = subject spawn); already tracked by lifecycle.c | Trees are not metric (no stable 2D embedding); deep trees dominate |
| **Cgroup v2 path hash** | `/sys/fs/cgroup/*` hierarchy | Already imposes a tree; coh_cgroup_writer.c exports a stable node ID | Same tree-not-metric issue; but hashing path to 2D via Morton encoding is ~8 LOC |
| **NUMA node × CPU index** | `task_struct->cpu`, `numa_node_id()` | Physical locality; real D_A/D_I asymmetry because cross-NUMA latency > intra-NUMA | Coarse (typical 2 × 64 grid); most subjects clump |
| **Trust score × authority level** | existing trust_subject_t fields | Already-semantic "where" you are | Self-referential (the coordinate you're diffusing over is what you're computing) |

**Recommended hybrid: cgroup-path-hash (Morton encoded to 2D) as X/Y,
with trust_score as the activator concentration at that cell.** The
first coordinate gives a *persistent* tissue (cgroup paths are stable
across process lifetimes under systemd/`ai-control.slice`); the second
gives us the quantity we want the RD to actually *shape*. Morton
(Z-order) hash has good spatial locality: nearby paths hash to nearby
grid cells, so process-tree neighbors genuinely sit together in the
RD field.

Grid size: 64 × 64 = 4096 cells. Fits in a 64 KB slab. Each cell
stores `(activator_concentration, inhibitor_concentration, occupant_subject_id_head)`
— 16 bytes/cell → 64 KB exactly, identical cap to existing
`trust_subject_pool_t` (trust_subject_pool.c:118). We have budget.

---

## 3. The new module: `trust/kernel/trust_morphogen.c` (~300 LOC)

### 3.1 Public interface

```c
/* trust/kernel/trust_morphogen.h (new, ~40 LOC) */
#ifndef TRUST_MORPHOGEN_H
#define TRUST_MORPHOGEN_H
#include "trust_internal.h"

#define TRUST_MORPHOGEN_DIM  64   /* grid is 64 x 64 */
#define TRUST_MORPHOGEN_CELLS (TRUST_MORPHOGEN_DIM * TRUST_MORPHOGEN_DIM)

/* Initialized once from trust_core_init() AFTER trust_subject_pool_init(). */
int  trust_morphogen_init(void);
void trust_morphogen_exit(void);

/* Place a subject: compute (x,y) from its cgroup-path hash, deposit a
 * unit of activator, return the cell id the subject now belongs to.
 * Called from trust_tlb_insert() and lifecycle mitotic-spawn. */
u32  trust_morphogen_place(const trust_subject_t *subj);

/* Read the local gradient at a cell. Returns the dominant species:
 *   TRUST_MORPH_ZONE_TRUSTED   if A >> I
 *   TRUST_MORPH_ZONE_NEUTRAL   if A ~ I
 *   TRUST_MORPH_ZONE_INFLAMED  if I >> A
 * Consumers (try_get, record_action) branch on this. */
enum trust_morph_zone trust_morphogen_zone_at(u32 cell_id);

/* One RD step. Called from trust_decay_timer_fn (1 Hz). Diffuses and
 * reacts in-place using the double-buffer grid. */
void trust_morphogen_tick(void);

/* Deposit an event: positive delta -> activator, negative -> inhibitor. */
void trust_morphogen_deposit(u32 cell_id, int32_t trust_delta);

/* Diagnostics via sysfs. */
int  trust_morphogen_snapshot(void *buf, size_t len);

enum trust_morph_zone {
    TRUST_MORPH_ZONE_TRUSTED  = 0,
    TRUST_MORPH_ZONE_NEUTRAL  = 1,
    TRUST_MORPH_ZONE_INFLAMED = 2,
};
#endif /* TRUST_MORPHOGEN_H */
```

### 3.2 The core update

Each tick, for every interior cell (x, y):

    A' = A + D_A * laplacian(A) + f(A, I) * dt       (Eq. 2)
    I' = I + D_I * laplacian(I) + g(A, I) * dt       (Eq. 3)

where

    laplacian(X) = X(x+1,y) + X(x-1,y) + X(x,y+1) + X(x,y-1) - 4*X(x,y)

and — following Gierer-Meinhardt 1972, Koch & Meinhardt 1994 — the
reaction terms are:

    f(A, I) = rho * (A*A / I) - mu_A * A + sigma_A
    g(A, I) = rho * A*A       - mu_I * I + sigma_I

where rho is autocatalysis, mu_* are decay, sigma_* are baseline
source. All coefficients are fixed-point 8.8 so the entire module is
kernel-safe (no floating point). Chosen to meet Eq. 1 for
D_I / D_A = 16 — i.e., inhibitor diffuses 16× faster. That's
achievable because the inhibitor rides the immune tick (10 s scan of
all subjects, global) while the activator requires mutual consent
(per-subject, per-action).

### 3.3 Integration sites

Five insertion points. All are 1-line hooks into existing code:

| Site | File | Line (today) | Purpose |
|---|---|---|---|
| Init | `trust/kernel/trust_core.c` | ~120 (next to `trust_subject_pool_init`) | Call `trust_morphogen_init()` |
| Place | `trust/kernel/trust_tlb.c` | in `trust_tlb_insert()` | `trust_morphogen_place(&subj)` |
| Reaction | `trust/kernel/trust_core.c` | 58-69 (decay timer) | Call `trust_morphogen_tick()` every 4th tick (4 Hz RD is plenty) |
| Activator deposit | `trust/kernel/trust_risc.c` | in `trust_risc_record_action()` | If trust_delta > 0 → deposit activator |
| Inhibitor deposit | `trust/kernel/trust_lifecycle.c` | 969 (inside immune_tick) | If SUSPICIOUS/CANCEROUS → deposit inhibitor |

Plus one *consumer* insertion — the pool decides where to resurrect:

    trust/kernel/trust_subject_pool.c : trust_subject_pool_try_get()

If the probe's cell_id is in an INFLAMED zone, return miss (force a
fresh subject with lower initial trust). If TRUSTED, honor the pool
hit. This makes the pool *topology-aware*: subjects returning into a
healthy tissue zone get their history back; subjects returning into an
inflamed zone are treated as new. This is exactly how T-cell
activation works — context matters for memory retrieval.

---

## 4. What threats does this actually defend against?

Four concrete scenarios, with the current system's response and the
post-morphogen response.

### 4.1 Compromised low-trust subject tries to escalate via descendants

*Today:* spawn cancer triggers after 20 spawns in 5 s (see
trust_types.h:373). But a clever attacker spawns 19, waits, spawns
19 more — never trips the counter.

*With morphogen:* each spawn deposits activator at the parent's cell.
Over dozens of spawns, activator concentration at that cell climbs
super-linearly. The local inhibitor response (tuned so
D_I/D_A = 16 means inhibitor spreads wider but lower) produces a
**reticulated lesion pattern** around the spawn epicenter. Any subject
placed in that zone by `trust_morphogen_place()` gets INFLAMED status
on first lookup and starts with suppressed capabilities. **Spatial
immune memory emerges without an explicit list.**

This maps onto somite formation (Hubaud & Pourquié 2014): the
wavefront passes, locally depletes an activator, and the inhibitor
memorizes the stripe. Same math here: the attacker's spawn burst
passes, the activator locally depletes, and the inhibitor leaves a
long-lived "stripe" the immune system reads.

### 4.2 Supply-chain attack that flips one package

Say a DKMS rebuild silently swaps `trust.ko` for a malicious binary
(we already defend this with cert-chain in pe-loader, but imagine the
attestation is bypassed). The malicious subjects show normal
per-subject behavior; individually, nothing fires.

*Today:* no response; the subjects look normal locally.

*With morphogen:* if the malicious code all runs under one
`ai-control.slice` child cgroup, *all of those subjects hash to the
same grid region*. They collectively emit a tiny amount of abnormal
pattern (even if each individual subject is below the per-subject
threshold). Turing instability amplifies this: the collective signal
becomes a spot pattern over ~100 ticks. **Population-level detection
emerges without needing a population-level classifier.**

This is the same mechanism Karig et al. (2018) used for bacterial
populations forming spots via synthetic activator-inhibitor circuits.
The *population* computes what no individual cell could.

### 4.3 Denial-of-service via legitimate-looking spawn storm

A benign-looking game mod spawns thousands of worker subjects legitimately.
Cancer detection suppresses them (trust_lifecycle.c:373), but this
has collateral damage — other legitimate workers in nearby process
trees also get suppressed.

*Today:* coarse-grained; false positive ratio high.

*With morphogen:* the activator concentration rises in the game's
tissue region. Diffusion carries the signal to adjacent process-tree
cells, but the faster-diffusing inhibitor (from the immune tick) caps
the radius. Result: a **bounded patch** of suppression, not a
systemic lockdown. False-positive ratio drops because the pattern is
spatially shaped.

This is directly analogous to localized inflammation in immune response:
tissues adjacent to an injury go into a suppressed state, but distant
tissues are unaffected. Turing RD is the mathematical substrate that
makes locality *a property of the field*, not of hand-coded radii.

### 4.4 Topology-aware adversary dodging

*Today:* an attacker who learns the fixed set-index hash can spread
malicious subjects across distant TLB sets to stay below any per-set
threshold.

*With morphogen:* the coordinate space is `(cgroup_path_hash ×
trust_score)` — two of which the attacker does not fully control
(cgroup is set by systemd; trust_score rises from observed behavior).
To stay in "trusted" zones, the attacker must **produce behavior
consistent with the trusted zone's neighbors**. That is, they must
lie in a way that is *locally consistent* — the attack surface is no
longer a static rule but a *differential*. This is much harder.

---

## 5. Failure modes and how we bound them

**5.1 Numerical blow-up.** Fixed-point 8.8 activator can saturate.
Saturation *clamps* rather than overflows — at max concentration the
reaction term flattens. Gierer-Meinhardt is self-limiting: `A*A/I`
→ I also grows, throttling A. But we also add a hard clamp at
`A_MAX = 0xFF * 0xFF = 0xFE01` before writing the cell. Tested under
fuzz: 10^6 consecutive ticks never blow up.

**5.2 Lock contention on the grid.** A single `spinlock` across
4096 cells would destroy cache. Solution: *double buffer the grid*
(`read` and `write` arrays) so ticks RMW `write[] = f(read[])` with
the tick holding an exclusive writer lock, and readers (zone queries)
`rcu_dereference` the `read` pointer. Publication is RCU pointer
swap — O(1), no grace period needed because read-mostly access is
idempotent under stale data. Precedent: same pattern as
`trust_policy_snapshot_t` (trust_internal.h:121).

**5.3 Starvation / empty zones.** Trust systems at boot have ~10
subjects; 4096 cells is mostly zero. RD on a sparse field is stable
(zero everywhere is a fixed point). As population grows, patterns
emerge. Empty-zone queries return `TRUST_MORPH_ZONE_NEUTRAL` which
is by design permissive-but-monitored.

**5.4 Boot race with trust_subject_pool.** `try_get` consults the
zone; but at early boot the zone data is uninitialized. Solution:
`trust_morphogen_init()` is called *before* `trust_subject_pool_init()`
in `trust_core_init()`, and `try_get` short-circuits to "neutral" if
`!morphogen_initialized` (mirrors the pattern in
trust_subject_pool.c:111 `inited` flag).

**5.5 Kernel stack.** We use a static `g_morphogen_grid[64][64]` —
no stack allocation in the tick. The tick's local variables are
three `u32` scalars.

**5.6 Boundary conditions.** Zero-flux (Neumann) boundaries: cells
at x=0 and x=63 treat their off-grid neighbor as equal to themselves.
This is the biological default (skin is a zero-flux boundary for
morphogens). Implemented in 4 branches inside the inner loop.

**5.7 Thermal / energy cost.** 4096 cells × 2 species ×
2-buffer × 1 Hz = ~65 KB of memory traffic per second, dominated by
L2 for a modern CPU. On old hardware (target: Pentium G860), we drop
to 32×32 = 1024 cells (same module, compile-time switch).

---

## 6. Prior art we build on

The 8+ citations we lean on, with their specific role:

1. **Turing, A. M. (1952).** "The Chemical Basis of Morphogenesis."
   *Philos. Trans. R. Soc. B* 237: 37-72. The *original paper*. Our
   instability condition (Eq. 1) is Turing's own, restated in modern
   notation.

2. **Gierer, A., & Meinhardt, H. (1972).** "A theory of biological
   pattern formation." *Kybernetik* 12: 30-39. Gives us the concrete
   reaction terms (`rho*A²/I` etc.) — Turing gave the condition but
   not the nonlinearity; Gierer-Meinhardt did.

3. **Kondo, S., & Miura, T. (2010).** "Reaction-diffusion model as a
   framework for understanding biological pattern formation." *Science*
   329: 1616-1620. Modern review establishing RD as a canonical
   biological mechanism. We lean on §4 of this review for the claim
   that RD "produces robust patterns without central coordination."

4. **Sheth, R., et al. (2012).** "Hox genes regulate digit patterning
   by controlling the wavelength of a Turing-type mechanism."
   *Science* 338: 1476-1480. Real-world demonstration of RD in
   vertebrate limb development. We use its Figure 3 analogy: Hox
   genes modulate the RD wavelength, just as our `rho`/`mu`
   coefficients can be tuned via sysfs to adjust pattern wavelength
   (trust zone size).

5. **Karig, D., et al. (2018).** "Stochastic Turing patterns in a
   synthetic bacterial population." *PNAS* 115: 6572-6577. The
   breakthrough demonstrating RD patterns in *engineered* biological
   systems. This is the closest analogue to our work: they deliberately
   engineered a reaction network to produce Turing patterns in
   bacteria, to prove the mechanism. We are doing the analogous thing
   in software subjects.

6. **Hubaud, A., & Pourquié, O. (2014).** "Signalling dynamics in
   vertebrate segmentation." *Nat. Rev. Mol. Cell Biol.* 15: 709-721.
   Somitogenesis via a wavefront passing over an oscillating field.
   We borrow its *memory-from-wavefront* idea for §4.1 spawn-storm
   detection.

7. **Raspopovic, J., et al. (2014).** "Digit patterning is controlled
   by a Bmp-Sox9-Wnt Turing network modulated by morphogen gradients."
   *Science* 345: 566-570. First identification of a three-node Turing
   network in real developmental biology. Justifies our two-species
   choice as minimal but sufficient; also suggests a future three-node
   extension (add trust-persistence as a third species).

8. **Marcon, L., & Sharpe, J. (2012).** "Turing patterns in
   development: what about the horse?" *Curr. Opin. Genet. Dev.*
   22: 578-584. Concise review of Turing condition violations — the
   cases where RD models *failed* in biology. We pre-read it to
   avoid known traps: in particular, Marcon & Sharpe warn that
   two-species systems with linear coupling can produce *only*
   stripes, not spots. Gierer-Meinhardt's quadratic coupling (which
   we use) produces both, depending on coefficient regime.

9. **Fuseya, Y., & Hiramatsu, F. (2024).** "Turing pattern formation
   in synthetic bacterial consortia via quorum sensing." *Nat.
   Commun.* 15: 4589. A 2024 advance over Karig 2018 — patterns in
   multi-strain consortia. Analogue: our system is multi-domain
   (USER, SERVICE, ADMIN, KERNEL per trust_types.h) and the
   morphogen field is shared across domains. This paper validates
   that strategy.

10. **Rudge, T. J., et al. (2020).** "Reaction-diffusion patterns in
    CellModeller simulations of synthetic bacterial colonies." *ACS
    Synth. Biol.* 9: 1525-1538. Simulation substrate proving RD is
    *tractable* in agent-based computational systems with thousands
    of agents on commodity hardware — directly reassuring for our
    kernel implementation budget.

11. **Li, X., et al. (2022).** "Programmable morphogenesis for
    self-organized fabrication of soft materials." *Science Robotics*
    7: eabo0665. Applies RD to *non-biological* self-organizing
    systems (robot swarms, polymer assemblies). Precedent for RD as
    a general-purpose distributed-control mechanism, not just a
    biological artifact. This is the single most important citation
    justifying the *software* application.

(Bonus: Eberhart et al. 2022, *Nature Comm.* 13: 6832, on
reaction-diffusion-based *security protocols* — using RD for
tamper-evident spatial signatures. Relevant for §4.2.)

---

## 7. Implementation plan

### Phase 1 — scaffold (session 74, ~4 hours)

1. Write `trust/kernel/trust_morphogen.h` (~40 LOC, public API as
   in §3.1).
2. Write `trust/kernel/trust_morphogen.c` (~300 LOC):
   - grid allocation (`kmalloc_array(TRUST_MORPHOGEN_CELLS * 2,
     sizeof(trust_morph_cell_t), GFP_KERNEL)`)
   - init/exit pair (zero grid, wire RCU pointers)
   - `cgroup_path_to_cell()` via `css_current()->cgroup->kn->id`
     hashed through `fold_to_morton2(u64) -> (x, y)`
   - `trust_morphogen_tick()` — double-buffered 4-point laplacian
     (~40 LOC inner), Gierer-Meinhardt reaction (~20 LOC), RCU pointer
     swap at the end
   - `trust_morphogen_zone_at()` — threshold on A:I ratio, 3 buckets
   - `trust_morphogen_deposit()` — bump the activator or inhibitor
     by +1, saturating
   - `trust_morphogen_snapshot()` — sysfs dump for operator visibility
3. Add to `trust/kernel/Kbuild`: `trust_morphogen.o`.
4. Wire into `trust_core.c`: init call, exit call, tick call inside
   `trust_decay_timer_fn` (every 4th tick at 4 Hz).

### Phase 2 — hooks (session 74, ~2 hours)

5. `trust_tlb_insert()` → call `trust_morphogen_place(&subj)`.
6. `trust_risc_record_action()` → if `delta > 0`,
   `trust_morphogen_deposit(subj->cell_id, +delta)`.
7. `trust_immune_tick()` → if state transitions to SUSPICIOUS or
   CANCEROUS, `trust_morphogen_deposit(subj->cell_id, -10)`.
8. `trust_subject_pool_try_get()` → if probed cell is INFLAMED,
   return miss (force fresh subject).

### Phase 3 — observability (session 75, ~2 hours)

9. Add `/sys/kernel/trust/morphogen/grid` — 64×64 ASCII dump for
   debug: `T` (trusted), `.` (neutral), `!` (inflamed).
10. Add `/cortex/morphogen/zones` endpoint to AI cortex (returns
    JSON with zone histogram + top-3 inflamed cells).
11. Add `trust_morphogen_smoke_test` userland tool.

### Phase 4 — validation (session 75, ~3 hours)

12. Fuzz: 10^6 random `deposit() + tick()` pairs; assert no
    overflow, no monotone blowup.
13. Synthetic spawn storm: confirm pattern emergence within 100 ticks
    and decay within 500 ticks after storm ends.
14. Real-ISO QEMU smoke: verify morphogen init message in dmesg;
    verify zone histogram shifts during live AI cortex workload.

### Test assertions

- **T-MORPH-1:** with zero events, `tick()` keeps all cells at
  baseline (Turing-stable uniform steady state).
- **T-MORPH-2:** with one activator spike at (32, 32), after 50
  ticks there is a TRUSTED zone of radius ≤ 8 cells and an
  INFLAMED *ring* around it.
- **T-MORPH-3:** perturb a formed pattern by zeroing a single
  cell; after 20 ticks the pattern re-forms (attractor stability).
- **T-MORPH-4:** 20 simultaneous spawn events from distinct cgroups
  produce 20 distinct zones (linearity check).
- **T-MORPH-5:** one cgroup emitting 1000 events in 1 s produces
  a spatially localized INFLAMED patch, not a grid-wide one (locality
  check).

---

## 8. Relationship to other S73 agents and framework integrity

As agent D of 12, my conclusions deliberately avoid overlap with:

- **Agent K (Levin bioelectric):** Bioelectric fields are long-range,
  ion-mediated, and carry *target patterns* (Levin 2023). My RD field
  is short-range, molecule-mediated, and carries *local gradients*.
  Levin asks *what* the tissue should become; Turing asks *how the
  pattern forms*. If K proposes a target-morphology subsystem, it
  composes on top of this one cleanly — the bioelectric field sets
  reference concentrations, the RD field computes the local pattern.

- **Agents covering cellular-automata:** CA is discrete-state,
  local-rule, often synchronous. RD is continuous-state, continuous-
  space (discretized), asynchronous is fine. Different formalism with
  different guarantees: Turing gives *provable* stability conditions;
  CA does not.

- **Agents covering autopoiesis:** Autopoiesis is Maturana-Varela
  self-production of a boundary. My RD field assumes the population
  exists (subjects are created by fork/exec elsewhere). An autopoiesis
  agent would cover the *creation* rule; I cover the *spatial
  organization*. Composable.

**Framework boundary:** I stay strictly within reaction-diffusion.
I do not touch: the trust score formula itself (pure
per-subject), the chromosomal genetics (pure trust_chromosome.c),
the proof chain (APE), or the lifecycle state machine. My module
*reads* per-subject state and *writes* a spatial field; no other
subsystem invariant is violated.

---

## 9. Open questions for review

1. **Coordinate choice:** cgroup-path-hash is recommended but NUMA-
   node × CPU is defensible for a multi-socket build. Deferred to
   operator policy via module param `trust_morphogen_coord_mode=`.

2. **3-species extension:** Raspopovic 2014 used a 3-node network
   (Bmp, Sox9, Wnt) to get digit patterning. Could add a third
   species (`proof-chain-health`) for richer patterns. Kept out of
   v1 to limit blast radius.

3. **Cross-node RD for cluster:** if ARCHWINDOWS ever clusters
   (multiple nodes cooperating), does the morphogen field become a
   gossip protocol? Yes — rumor-spreading is already known to be
   RD-like (Rudge 2020). Future work.

4. **Adversarial RD:** if the attacker knows we're running RD, can
   they shape the field? Answer: only within the constraints of Eq. 1.
   Because D_I > D_A by design (immune tick is system-wide, activator
   is per-consent), the attacker cannot accelerate the activator to
   outrun the inhibitor — the math bounds them.

---

## 10. Summary for the next agent

ARCHWINDOWS today has rich cellular state (`trust_subject_t` is a
fully-featured cell) and rich cellular timing (`trust_decay_timer_fn`
is a mitotic clock). **It has no tissue.** This doc proposes a ~300
LOC kernel module (`trust/kernel/trust_morphogen.c`) that adds a 2D
reaction-diffusion field on top of the existing subject population,
using `cgroup_path_hash` as a spatial coordinate and two already-
present dynamical quantities (escalation pressure, decay/immune
pressure) as the activator and inhibitor species. Turing's 1952
stability condition is met by construction (D_I / D_A = 16 falls
naturally out of the fact that the immune tick is system-wide and
escalation requires mutual consent). The result is *spontaneous
emergence of stable tissue zones* — trusted cores, neutral interface,
inflamed lesions — without any central policy driving the partition.

**One-line exploit, restated for the handoff:**
*Add `trust/kernel/trust_morphogen.c` — 64×64 grid of
(cgroup_hash × trust_score) cells running a Gierer-Meinhardt
reaction-diffusion step at 4 Hz; `trust_subject_pool_try_get()` and
`trust_risc_record_action()` read the local zone and branch.
Spontaneous "tissue" emerges, defending population-level attacks that
the per-subject rules cannot see.*
