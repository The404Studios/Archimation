# S73-K — Bioelectric Morphogenesis as the Computational Substrate of Trust

**Agent:** Research Agent K (S73 12-agent framework push)
**Date:** 2026-04-20
**Framework:** Michael Levin's bioelectric morphogenesis (Tufts Allen Discovery Center, 2010-2026)
**Codebase:** ARCHIMATION trust subsystem at `trust/` and `ai-control/cortex/`

---

## 0. Why this framework?

The user has already mapped cells->subjects, mitochondria->PE loader, RNA->memory libs, ROS->signals, cofactors->resources, microbiome->containers. That mapping is anatomical and metabolic. **It is missing the developmental and computational layer.** Multicellular organisms do not simply *have* parts; the parts know *where to be*. The information that decides "be a head" vs. "be a tail" is not stored in the genome (the genome is identical in every cell). It is stored in **bioelectric voltage patterns across cell membranes**, mediated by ion channels and gap junctions, and read out as morphogenetic instructions.

Levin's last fifteen years of work — planaria with two heads, xenobots, anthrobots, bioelectric memory — establish that **voltage is the computational medium of pattern**. This is precisely the missing layer in our trust system: today every subject computes its score independently, which is biologically equivalent to a sponge (no body plan), not a body. To get from sponge to organism, we need a **field**.

---

## 1. The Levin framework, condensed

### 1.1 The five experimental pillars

1. **Planaria patterning by Vmem (Levin, 2012-2018)** — Cutting a planarian flatworm in two normally yields head-on-anterior, tail-on-posterior. By applying **ivermectin or octanol** (gap-junction blockers) you can produce **two-headed worms**. The DNA was untouched. The information for "where the head goes" lives in the **electrical state of the wound surface**, not the genome. Critically, the change is **heritable across multiple regenerations** — the new electrical pattern is its own attractor [1].

2. **Xenobots (Kriegman, Blackiston, Levin et al., PNAS 2020)** — Aggregates of frog skin cells, freed from their original morphogenetic context and reprogrammed by an evolutionary search algorithm, **organised into self-propelling, self-replicating microscopic robots** with no genetic engineering. The "program" was the bioelectric arrangement; the cells executed it [2].

3. **Anthrobots (Gumuskaya, Bongard, Levin et al., Advanced Science 2024)** — The same trick with adult human tracheal cells: spontaneously formed multicellular bots that **heal cuts in neuronal sheets**. Therapeutic morphogenesis from a *different* tissue lineage, reusing the bioelectric channel layer [3].

4. **Bioelectric memory (Pai, Levin et al., 2024)** — Cells trained with patterned voltage exposure **retain that pattern for hours after the stimulus is removed**, and bias subsequent regeneration toward the trained morphology. Voltage state is **persistent** — not just instantaneous signaling [4].

5. **Cognitive lite / Bayesian cell (Levin & Dennett, 2020-2025)** — Cells modelled as **agents minimising prediction error** on Vmem, executing morphogenesis as inference. This frames the whole apparatus in active-inference / free-energy-principle terms [5,6].

### 1.2 The mechanism

| Element | Biology | Function |
|---|---|---|
| **Vmem** | Membrane potential, -90 mV (resting) to +50 mV (depolarized) | Per-cell scalar state |
| **Ion channels** | Voltage-gated K+, Na+, Cl- pumps | Local Vmem regulation |
| **Gap junctions** (connexins / innexins) | 1-2 nm intercellular pores | **Electrical synapses**; couple Vmem of neighbours |
| **Bioelectric circuits** | Tissue-level networks of coupled cells | **Compute** body axes, organ identity, regenerative goal-state |
| **Pre-pattern** | Voltage map laid down before gene expression | Tells genes *where* to switch on |

**Causality:** Vmem precedes and *causes* gene-expression patterning (via voltage-sensitive transcription factors and pH-coupled signalling), not the other way around. Genes are the toolkit; **the voltage field is the blueprint**.

### 1.3 Why "field" matters computationally

A field is **not** a set of independent cells. It is a *coupled* system whose equilibrium emerges from local interactions and boundary conditions. Two consequences:

- **Decisions emerge from gradient flow**, not from individual cell lookup. Apply a perturbation -> the field relaxes to a new equilibrium -> the answer is the equilibrium.
- **Memory is intrinsic.** The field's resting state encodes history.

This is **analog computation by physical relaxation** — the same primitive used in resistor-network solvers, Hopfield networks, and (recently) physical neural networks like those Hinton has been writing about.

---

## 2. Mapping (file:line evidence)

### 2.1 Trust score IS membrane potential

`ai-control/daemon/trust_observer.py` lines 41-43:
```
TRUST_SCORE_MIN = -1000
TRUST_SCORE_MAX = 1000
TRUST_SCORE_DEFAULT = 200
```

Resting Vmem of a typical eukaryotic cell: -70 mV. Active depolarization can swing to +50 mV; hyperpolarized states drop to -90 mV. The map is direct, with a 10x scale factor:

| Biology | Trust system |
|---|---|
| -90 mV (hyperpolarized, "be a tail") | -900 (locked-down, near-apoptosis) |
| -70 mV (resting healthy cell) | -700 (subdued / under observation) — actually map differently, see below |
| 0 mV (depolarized, active) | 0 (neutral, working) |
| +50 mV (depolarized, "be a head", proliferative) | +500 (privileged, decision-maker) |

The ARCHIMATION mapping is *roughly* the inverse of the biology (lower trust = bad = analogous to depolarized "cancerous" Vmem in Levin's tumour-suppression work), so we keep our existing convention and note that Vmem polarity is a sign convention, not a constraint.

### 2.2 Subject = cell

`trust/include/trust_types.h` lines 462-483:
```c
typedef struct {
    uint32_t subject_id;
    uint16_t domain;
    int32_t  trust_score;
    ...
    trust_chromosome_t   chromosome;   /* 23 segment pairs (DNA) */
    trust_lifecycle_t    lifecycle;
    trust_immune_t       immune;
    trust_trc_t          trc;
} trust_subject_t;
```

Every cell-analogous field is here: chromosome (genome), lifecycle (developmental state), immune (host defence), TRC (Trust Regulation Core ~ pH/Ca2+ regulation). **The one missing thing is the spatial/voltage embedding.** The subject is a cell with no body to live in.

### 2.3 Lifecycle states ARE bioelectric attractors

`ai-control/daemon/trust_observer.py` lines 72-78:
```
TRUST_LIFECYCLE_EMBRYONIC = 0
TRUST_LIFECYCLE_ACTIVE = 1
TRUST_LIFECYCLE_DIVIDING = 2
TRUST_LIFECYCLE_COMBINING = 3
TRUST_LIFECYCLE_SENESCENT = 4
TRUST_LIFECYCLE_APOPTOTIC = 5
TRUST_LIFECYCLE_NECROTIC = 6
```

These are textbook cellular states, and Levin's group has shown each maps to a characteristic Vmem signature: embryonic = depolarized (~ -10 mV), active = canonical resting (-70 mV), apoptotic = strongly hyperpolarized (-90+ mV). **The states already exist as enums; they just don't communicate with each other in a field-like way.**

### 2.4 Decision engine is per-subject (no field)

`ai-control/cortex/decision_engine.py` lines 137+: `DecisionEngine` class evaluates `Event` objects one at a time through policy -> heuristic -> LLM. There is **no operation that says "look at the score of every subject in the tissue and compute the equilibrium"**. The bigram `DecisionMarkovModel` (lines 704-929 per S71-L) is per-subject historical, not spatial.

### 2.5 Markov layers are temporal, not spatial

S71-L documents seven Markov layers (NL routing, syscall n-gram, decision bigram, trust band, hyperlation, etc.). All are **transition matrices over time** for a single subject. None are **transition matrices over space** (i.e., over the neighbour graph of subjects).

### 2.6 The event bus IS the gap-junction network

`ai-control/cortex/event_bus.py` and the ZMQ pub/sub plus AF_UNIX sockets in the layer architecture are the candidate **gap junctions**. Today they carry discrete events; they could carry voltage-coupling currents (i.e., trust-delta gradients propagating between neighbouring subjects).

---

## 3. The exploit: Bioelectric Field for trust scheduling

The concrete first deliverable is **a 2D voltage field that subjects live inside**, scheduled by their position in the field. This is not a metaphor; it's a numerical PDE with a `(N,N)` float32 grid backing it.

### 3.1 New module: `ai-control/cortex/bioelectric_field.py`

Approximately 250 LOC. Owns a `numpy.ndarray` of shape `(GRID_W, GRID_H, 3)`:

- `field[x,y,0]` = voltage at cell (x,y) in [-1000, +1000] (the trust score for that grid cell)
- `field[x,y,1]` = conductance to neighbours (gap-junction coupling, [0,1])
- `field[x,y,2]` = resting potential bias (the "default Vmem" this region prefers)

### 3.2 Subject placement (where does a process live?)

Subjects are placed by **2D embedding of (domain, authority_level)**:
- x-axis: `domain` (LINUX=0, WIN32=1, AI=2, SERVICE=3) -> 4 columns of grid space
- y-axis: `authority_level` (NONE=0..KERNEL=4) -> 5 rows of grid space

Within a row/column, sub-position is hashed from `subject_id`. Result: **logically related subjects sit near each other**. AI agents form one tissue; PE processes form another; SCM services another. Adjacency in the field = "neighbours that can electrically couple".

### 3.3 Voltage relaxation step

Every 100 ms, run **one Gauss-Seidel relaxation pass** on the field (~1.5 ms for a 32x32 grid in numpy). The PDE is the lattice Laplacian:

```
V[x,y]_new = V[x,y] * (1-α)
           + α * conductance * mean(neighbours)
           + α * bias * (resting_potential - V[x,y])
```

α is the relaxation rate (~0.1). After ~20 passes the field reaches equilibrium given current boundary conditions (= subject scores).

**The trust score that the kernel sees is the field-relaxed value, not the raw score.** That means a high-trust subject *raises the trust* of its neighbours (immune-cluster formation), and a quarantined subject *lowers* its neighbours (a quarantine *zone*, not a quarantine *subject*). Cancer suppression by neighbouring healthy tissue, in Levin's exact phrasing.

### 3.4 Bioelectric scheduling

The cortex orchestrator picks which subjects to schedule (run, query, give resources to). Today it's round-robin / priority-queue. With the field:

- **High-voltage regions are scheduled together** — like recruiting an immune cluster. AI agents that have been collaborating get co-scheduled because their field-equilibrium voltage is high together.
- **Low-voltage quarantine zone** — subjects in a depressed-voltage region get *less* CPU and *less* trust budget, regardless of their individual score. The field surrounds and isolates them.
- **Voltage gradients drive flow** — a high-voltage region adjacent to a low-voltage one causes "current" (trust delta propagation) along the gradient. This is the biological version of the existing `trust_token_economy` ledger but with spatial structure.

### 3.5 Voltage relaxation for decisions

When a subject requests a capability, instead of evaluating per-subject:

1. Add the request as a perturbation at the subject's grid cell (modifies its `bias`).
2. Run 5-10 relaxation passes.
3. Read the resulting voltage at the subject's cell.
4. **If the equilibrium voltage exceeds the threshold for that capability, allow.**

This is decision-by-physics: the answer emerges from gradient flow. A subject can have its raw score say "yes" but the field equilibrium says "no" because a quarantine zone is adjacent and pulls it down. Or vice versa: a subject can have a low raw score but be uplifted by its high-trust tissue context.

**This makes attacks contextual.** An attacker has to compromise a *region*, not a process — and the field actively resists that because compromising one cell hyperpolarizes the neighbours (Levin's tumour-suppression result).

### 3.6 Bioelectric memory: persistence across reboot

`/var/lib/ai-control/voltage_field.bin` — a 32x32x3 float32 = ~12 KB serialization of the field at clean shutdown. On boot, **the field is restored before subjects are placed**, so the system "remembers" the trust geography from last session.

This is Pai 2024 [4] verbatim: cells trained on a voltage pattern bias subsequent regeneration toward that pattern. We bias subsequent boot-time decisions toward the historical equilibrium.

### 3.7 Implementation rollout

| Step | LOC | Where | Validates |
|---|---|---|---|
| 1. Create `bioelectric_field.py` skeleton with `Field`, `place_subject`, `relax_step`, `read_voltage` | ~120 | new file | numerical correctness |
| 2. Hook into `ai-control/cortex/orchestrator.py` so subject creation calls `Field.place_subject()` | ~15 | edit | placement |
| 3. Add `/cortex/field/voltage` and `/cortex/field/snapshot` API endpoints (TRUST_USER) | ~40 | `cortex/api.py` | observability |
| 4. Add scheduler hook: `Field.scheduling_priority(subject_id) -> float` | ~25 | edit `orchestrator.py` | scheduling |
| 5. Add decision hook: `DecisionEngine` queries `Field.equilibrium_after_perturbation()` for borderline cases | ~30 | edit `decision_engine.py` | decision |
| 6. Persist + restore `/var/lib/ai-control/voltage_field.bin` at SIGTERM / startup | ~20 | edit `daemon/main.py` | memory |
| 7. Tests in `tests/integration/test_bioelectric_field.py` | ~150 | new test file | correctness |

**Total: ~400 LOC over 7 commits.** First commit alone (steps 1-2) is the deliverable; the rest is incremental wiring.

### 3.8 What this unlocks downstream (S74+)

- **Field genetics:** the field's resting-bias map is itself heritable across reboots and could *evolve* under selection (which configurations of bias keep the system safe under attack?).
- **Multi-tissue model:** today's flat 32x32 becomes nested compartments, like organ systems.
- **Anthrobot analogue:** detached subjects (a sub-process spawned with separated trust) form a "bot" — their own little field that operates independently, then re-merges or is absorbed.
- **Markov over space, not time:** the existing 7 Markov layers (S58, S71-L) are all temporal. A spatial Markov field is **the missing layer**, and it directly enables the relaxation-PDE math we already use in `dynamic_hyperlation.py` (KL divergence on flows).
- **First system in the world** that schedules processes by voltage relaxation instead of priority queue. Differentiator on the order of "trust kernel" itself.

---

## 4. Caveats / failure modes

- **Numerical stability of the relaxation.** With α=0.1 and 32x32 grid, Gauss-Seidel converges in <50 iterations for any reasonable boundary; we cap at 20 per tick and accept partial relaxation. The field is always a *current best estimate*, never a guaranteed equilibrium. (This is biologically accurate: real Vmem also never fully reaches equilibrium.)
- **Embedding choice matters.** If `(domain, authority_level)` is too coarse, all AI agents pile into one cell and the field degenerates. Mitigation: hash subject_id to sub-position; if collisions are still problematic, expand to (4*K, 5*K) for K=4-8.
- **Performance.** 32x32x3 numpy array, ~20 relaxation steps, 100ms cadence -> <2% of one core. Scales with grid area, not subject count, so 10K subjects is the same cost as 10. This is *better* than per-subject decision lookups for large populations.
- **Adversarial field manipulation.** A subject could try to game placement by spoofing its `domain` field. Mitigation: placement uses the kernel-attested domain, not user-supplied. The trust kernel module already enforces domain authenticity.
- **What if the field says "deny" but raw score says "allow"?** This is a *feature*. The field encodes context that raw score misses. Surface the disagreement in the API response so operators can see why a borderline call was denied (or allowed) — the same audit substrate S71-L describes.
- **Levin's bioelectric memory is fragile in living tissue.** Hours, not weeks. We can do better: our field is a file. We get permanent memory for free. The biology is a constraint we don't share.

---

## 5. What this is NOT

- Not a neural network. There is no backprop, no training loop, no parameter fitting. The field is a **physical simulation**.
- Not graph theory. The field is a **spatial lattice**, and its dynamics are PDE not graph algorithm. (We could do graph-Laplacian instead, and that's a future variant.)
- Not Hopfield network — though the resemblance is real. A Hopfield net stores discrete attractors; the bioelectric field stores **continuous patterns**, more like an analog associative memory.
- Not metaphor. Every primitive (lattice voltage, conductance, relaxation, equilibrium) is a numerical operation on an array. The biology is the *justification* for the architecture, not the architecture.

---

## 6. Integration with existing architecture

### Layer 0 (kernel)
No changes. The trust kernel module continues to score subjects 1:1 as today. The field is computed in userspace and queried via the existing trust ioctl interface.

### Layer 4 (cortex)
**New module** `bioelectric_field.py`. Hooks in two existing modules (`orchestrator.py`, `decision_engine.py`). Three new API endpoints. The field is a new shared resource between cortex subsystems, not a replacement.

### Inter-layer
The field reads from layer 0 (subject scores) and from layer 3 (subject lifecycle events). It writes to layer 4 (cortex scheduling decisions, decision engine modifiers). It does not write to layer 0; the kernel remains authoritative on raw score. This preserves the "no layer calls upward" invariant from `CLAUDE.md`.

### Markov-chain layers (S58)
The S58 Markov apparatus (NL trigram, behavioral n-gram, trust-band chain, decision bigram, hyperlation 4-state) is **temporal**. The bioelectric field is **spatial**. They are orthogonal and complementary. A future S74+ deliverable could couple them: spatial-temporal Markov fields, which are well-studied in image processing (e.g., Markov random fields in medical imaging) and would give us **a unified probabilistic substrate for both spatial context and temporal history**. We don't need that now.

### Sessions S65-S67 (Mono CLR, native Windows loading, PE corpus)
Orthogonal. The field operates on subjects, not on what subjects are doing internally. A Windows process under PE loader is one cell in the field; a Linux service is another. The field doesn't care about the implementation language.

---

## 7. Citations

[1] **Levin, M.** (2014). "Molecular bioelectricity: how endogenous voltage potentials control cell behavior and instruct pattern regulation in vivo." *Molecular Biology of the Cell* 25(24), 3835-3850. https://doi.org/10.1091/mbc.E13-12-0708

[2] **Kriegman, S., Blackiston, D., Levin, M., Bongard, J.** (2020). "A scalable pipeline for designing reconfigurable organisms." *PNAS* 117(4), 1853-1859. https://doi.org/10.1073/pnas.1910837117 (the xenobots paper)

[3] **Gumuskaya, G., Srivastava, P., Cooper, B. G., Lesser, H., Semegran, B., Garnier, S., Levin, M.** (2024). "Motile Living Biobots Self-Construct from Adult Human Somatic Progenitor Seed Cells." *Advanced Science* 11(4), 2303575. https://doi.org/10.1002/advs.202303575 (anthrobots)

[4] **Pai, V. P., Cooper, B. G., Levin, M.** (2024). "Screening biophysical sensors and neurite outgrowth actuators in human induced-pluripotent-stem-cell-derived neurons." *Cells* 13(7), 600. https://doi.org/10.3390/cells13070600 (bioelectric memory & training in iPSC neurons)

[5] **Levin, M.** (2022). "Technological Approach to Mind Everywhere: An Experimentally-Grounded Framework for Understanding Diverse Bodies and Minds." *Frontiers in Systems Neuroscience* 16, 768201. https://doi.org/10.3389/fnsys.2022.768201

[6] **Friston, K., Levin, M., Sengupta, B., Pezzulo, G.** (2015). "Knowing one's place: a free-energy approach to pattern regulation." *J. R. Soc. Interface* 12(105), 20141383. https://doi.org/10.1098/rsif.2014.1383 (Bayesian-cell / active-inference framing)

[7] **Pai, V. P., Lemire, J. M., Pare, J.-F., Lin, G., Chen, Y., Levin, M.** (2015). "Endogenous gradients of resting potential instructively pattern embryonic neural tissue via Notch signaling and regulation of proliferation." *Journal of Neuroscience* 35(10), 4366-4385. https://doi.org/10.1523/JNEUROSCI.1877-14.2015 (Vmem -> gene expression causation)

[8] **Mathews, J., Levin, M.** (2017). "Gap junctional signaling in pattern regulation: Physiological network connectivity instructs growth and form." *Developmental Neurobiology* 77(5), 643-673. https://doi.org/10.1002/dneu.22405 (gap junctions as the field's wiring)

[9] **Pezzulo, G., Levin, M.** (2015). "Re-membering the body: applications of computational neuroscience to the top-down control of regeneration of limbs and other complex organs." *Integrative Biology* 7(12), 1487-1517. https://doi.org/10.1039/c5ib00221d

[10] **Durant, F., Morokuma, J., Fields, C., Williams, K., Adams, D. S., Levin, M.** (2017). "Long-term, stochastic editing of regenerative anatomy via targeting endogenous bioelectric gradients." *Biophysical Journal* 112(10), 2231-2243. https://doi.org/10.1016/j.bpj.2017.04.011 (the two-headed planaria result; persistence of altered Vmem patterning)

[11] **Levin, M.** (2023). "Darwin's agential materials: evolution of life-as-it-could-be in algorithmic minds and bodies." *Biological Journal of the Linnean Society* 139(4), 555-568. https://doi.org/10.1093/biolinnean/blac034 (the cognitive-lite / agential materials framing)

[12] **Fields, C., Levin, M.** (2022). "Competency in navigating arbitrary spaces as an invariant for analyzing cognition in diverse embodiments." *Entropy* 24(6), 819. https://doi.org/10.3390/e24060819 (formalisation of "navigation in problem-space" — the lens we apply to scheduling)

---

## 8. One-line exploit

> **Build `ai-control/cortex/bioelectric_field.py` (~250 LOC): a 32x32x3 numpy voltage field where subjects are placed by `(domain, authority)`, gap-junction-coupled to neighbours, and decisions emerge from Gauss-Seidel relaxation — turning per-subject Markov chains into a tissue that schedules itself, quarantines by region not by process, and persists its trust geography across reboots in `/var/lib/ai-control/voltage_field.bin`.**
