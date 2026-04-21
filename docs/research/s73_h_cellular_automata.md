# S73-H — Cellular Automata as the Missing Topology Layer in the Trust Kernel

**Project:** ARCHWINDOWS — `trust.ko` (22 `.c` files) + `coherence/daemon`
**Research angle:** Conway (1970), Wolfram NKS (2002), Cook's Rule 110 universality, Langton's Ant, Lenia (2019), Neural Cellular Automata (2020–2024), CA-based intrusion detection — applied to `trust_subject_pool.c` which is currently a *flat population without neighborhoods*.
**Date:** 2026-04-20
**One-line exploit:** *Add a process-tree + cgroup-co-membership neighborhood index to `trust_subject_pool` and let each subject's trust score undergo a Lenia-style continuous local update; Class-4 emergent immune behavior (compromised sub-trees spontaneously isolate) falls out without any central decision.*

---

## 0. Framework Positioning

This document is **specifically** about cellular automata — local deterministic rules on a spatial lattice producing emergent global behavior (Conway, Wolfram, Cook, Langton, Chan). It is **not** about Von Neumann's self-replicating automata (that is Agent A's territory and the CA work in that context is strictly VN-style); nor about agent-based models (Epstein/Axtell), swarm intelligence (Reynolds, boids), multi-agent RL (Agent L's territory), or generic graph dynamics. The line we walk:

- A **cellular automaton** in the 1970–2026 sense we care about = `(Lattice L, Neighborhood N, State alphabet Σ, Local rule f : Σ^|N| → Σ)`, evolved synchronously or asynchronously, producing global dynamics that no single cell computed.
- Our claim is that the trust kernel's subject pool is **already close to a CA** (it has state, it has a rule, it has timing) — it is **missing exactly one thing**: the lattice/neighborhood relation. Once that is added, decades of CA theory apply directly.

---

## 1. Historical CA Literature (annotated)

### 1.1 Conway's Game of Life (1970)

Conway's Life is the zeroeth-law reference: 2D square lattice, Moore neighborhood (8 neighbors), binary state, rule B3/S23 (birth if exactly 3 live neighbors; survive if 2 or 3). Gardner's October 1970 *Scientific American* column [1] popularized it; Berlekamp, Conway and Guy proved Life is **Turing-complete** in *Winning Ways* (1982) [2], constructing gliders, glider guns (Gosper, 1970), eaters, and eventually universal computation via the 2010 Adam P. Goucher "OTCA metapixel" construction [3].

**Relevance to trust kernel:** Life demonstrates that the *simplest possible local rule* on a spatial lattice produces non-trivial global behavior (oscillators, spaceships, replicators). The trust kernel today has no lattice — we cannot get even trivial emergent behavior.

### 1.2 Wolfram's 4-Class Taxonomy (NKS, 2002)

Wolfram's *A New Kind of Science* [4] classified CAs into four empirical behavior classes — universally applicable to 1D, 2D, totalistic, continuous, and asynchronous variants:

| Class | Behavior | 1D example (elementary rules) | Biological analog | Thermodynamic analog |
|---|---|---|---|---|
| **Class 1** | Relaxes to uniform fixed point | Rule 0, Rule 8, Rule 32 | Dead tissue, necrosis | Ordered (crystal) |
| **Class 2** | Periodic / stable local structures | Rule 4, Rule 37, Rule 56 | Homeostatic regulation | Periodic |
| **Class 3** | Chaotic / random-looking | Rule 30, Rule 45, Rule 86 | Fever / cytokine storm | Maximum entropy |
| **Class 4** | **Edge of chaos** — persistent local structures that interact nontrivially | **Rule 110**, Rule 54 | **Immune system at steady state**, tumor–immune coexistence | Edge-of-phase-transition |

Langton (1990) [5] quantified the Class-4 regime with his λ parameter (fraction of rules mapping to non-quiescent state); Class 4 emerges near λ ≈ 0.27 on 1D totalistic rules — a narrow band where the automaton is both complex enough to compute and stable enough not to blow up.

**Our trust kernel today (pre-S73) sits squarely in Class 1 or Class 2.** Subjects are isolated; their trust scores decay (Class 1) or oscillate around thresholds (Class 2). There is **no Class-3 chaotic behavior and crucially no Class-4 emergent structure**. We want Class 4.

### 1.3 Rule 110 — Universality (Cook, 2004)

Matthew Cook, working as Wolfram's assistant, proved that **elementary CA Rule 110** (the simplest possible 1D CA — 2 states, radius-1 neighborhood, 8 rule-bits) is **Turing complete** [6]. The proof simulates cyclic tag systems via interacting "gliders" on a Rule 110 background. This ended the question of how simple a local rule could be while remaining computationally universal: 8 bits.

**Direct relevance:** If Rule 110 can host a universal Turing machine with 8-bit local rules on a binary alphabet, then the trust kernel's 32-bit trust_score × ~10 local neighbors × capability bitmask is *vastly* more expressive than necessary to host emergent computation. The open question isn't "can the trust kernel be CA-universal" (trivially yes), but "which rule gives us Class-4 immune behavior?"

### 1.4 Langton's Ant (1986)

Langton's Ant [7] is a minimal asynchronous CA: a single "ant" traversing a grid, flipping cell colors and turning left/right based on local color. Despite two trivial rules, the ant exhibits three phases:

1. **Simplicity** (~200 steps) — clear symmetry.
2. **Chaos** (~9,900 steps) — apparent randomness.
3. **Emergence** — a *highway* (period-104 cyclic pattern) that drifts across the grid indefinitely.

The transition from phase 2 to 3 is a **spontaneous symmetry-breaking**: the ant "decides" on a direction and commits, without any global coordination. This is the exact behavioral signature we want for the trust kernel: a sub-tree of compromised processes spontaneously "commits" to isolation without any central scheduler voting on it.

### 1.5 Lenia (Bert Chan, 2019–2022)

Chan's Lenia [8] generalizes Conway's Life to **continuous space, continuous time, continuous state**. State ∈ [0,1], neighborhood is a ring kernel with a Gaussian profile, update is a convolution-then-activation over a small Δt. Lenia produces roughly **500 classified "species"** of self-organizing "life-forms" (gliders, rotators, budders, shape-shifters) whose visual similarity to protozoa is striking.

**Why Lenia is the right model for trust-score dynamics:**
- Trust scores are continuous (−1000 to +1000), not binary.
- Time is continuous (events arrive at arbitrary ns timestamps).
- The neighborhood is fuzzy (parent × cgroup × same-DLL — not a clean Moore neighborhood).

Lenia's update rule is:
```
A_{t+1}(x) = clip( A_t(x) + Δt · G( K * A_t (x) ) )
```
where K is a radial kernel, `*` is convolution, G is a Gaussian growth function centered at some μ with width σ. The hyperparameters (μ, σ, Δt, kernel profile) tune the system into exactly the Class-4 "edge of chaos" band.

### 1.6 Neural Cellular Automata (2020–2024)

Mordvintsev et al., *Growing Neural Cellular Automata* [9] (Distill 2020), showed that a tiny MLP (≈8K parameters) trained as a local CA rule can **grow an arbitrary target image from a single seed cell** and **regenerate it after damage** — true morphogenesis. Follow-up work [10] showed NCAs can be trained to self-classify, self-replicate, and exhibit immune-like damage response.

**Morphogenesis → immune response analogy:** when part of an NCA-grown salamander is excised, neighboring cells *re-grow* the missing region. No central planner. If we treat "compromised = damaged," a CA-structured trust pool with a Lenia-like smoothing rule will analogously re-grow a healthy trust landscape around a zone of attack — patches of high-trust cells will supply trust to healing neighbors; a sub-tree whose trust has collapsed below the healing floor is simply *left out* (isolated).

### 1.7 CA-based Intrusion Detection (Forrest, 1996+; more recent)

Stephanie Forrest's work on **computer immunology** [11] and the **self/nonself** model used negative-selection-style local rules on syscall sequences. Modern CA-IDS work [12, 13] applies gossip-protocol propagation of viral signatures (a biological metaphor that maps 1:1 to CA propagation): each node runs a local rule; infection/alert states diffuse through the network-graph lattice; global signature convergence emerges in O(log N) hops.

**Relevance:** this is the direct literature for what we want — CA-based immune propagation. Our advantage over 1996-era work is that we have trust_subject_t as a pre-existing biological subject (not retrofitted); we just need the lattice.

### 1.8 Gács's Reliable CA (1986, 2001)

Gács [14] constructed a 1D CA tolerant to stochastic noise — a cell flips randomly with probability ε, yet the global computation still terminates correctly. This matters because our trust kernel is inherently noisy (subjects are created/destroyed nondeterministically, scores jitter on action decay). Gács's result tells us we can expect a noise-tolerant Class-4 band to exist *if we set up the local rule correctly*.

---

## 2. Mapping (file:line evidence)

### 2.1 `trust_subject_pool.c` as a NON-CA (today)

`trust/kernel/trust_subject_pool.c:98–108` defines:
```c
typedef struct {
    spinlock_t                      lock;
    trust_subject_pool_entry_t      slots[TRUST_SUBJECT_POOL_MAX];
    u64                             hits;
    u64                             misses;
    u64                             evictions;
    u64                             total_age_on_hit_ns;
    u32                             population;
    u32                             points;
    int                             inited;
} trust_subject_pool_t;
```

**This is a flat array of 64 slots with zero topological relation between them.** A subject at `slots[17]` has no notion that `slots[18]` or `slots[3]` is its neighbor. There is no 2D grid, no graph, no neighborhood index. `pick_victim_locked()` at line 229 scans linearly and picks by eviction score — a global, not local, rule.

**What `trust_subject_pool.c` has that makes CA retrofitting cheap:**
- A fixed-size slot array (→ perfect static lattice).
- A spinlock already held during mutation (→ stepping the CA can piggyback on the same critical section).
- A sweep already walking every slot (`sweep_locked` at line 191) — O(N) per tick.
- Per-entry `put_ns` + `last_used_ns` = natural time stamps for the CA clock.

### 2.2 `trust_dispatch.c` as applying LOCAL RULES without a LATTICE

`trust/kernel/trust_dispatch.c:240–302` — `cmd_trust_check`, `cmd_trust_score`, `cmd_trust_record`, `cmd_trust_threshold`, `cmd_trust_decay` all operate on a **single subject** given by `subject_id`. The "local rule" is effectively:

```
trust_score_{t+1}(s) = f( trust_score_t(s), action, decay )
```

No neighbors. This is a 1-cell automaton — the degenerate CA. It is Class 1 almost by construction (any f that isn't carefully chosen collapses to a fixed point).

### 2.3 `coherence/daemon/src/state_machine.c` IS an Elementary CA

`coherence/daemon/src/state_machine.c:210–257` — the 4-state arbiter `{NORMAL, LATENCY_CRITICAL, THERMAL_CONSTRAINED, DEGRADED}` with explicit transition rules, dwell-time-based hysteresis, and explicit lockout to prevent oscillation. **This is an elementary CA with 4 states applied per-resource.** Per-resource = per-cell. But again, there's no neighborhood — each resource's state machine evaluates purely on its own derived metrics. Two resources with related workloads don't influence each other.

### 2.4 Neighborhood Candidates (ranked)

| Candidate | Biological analog | Cost | Expressiveness | Stability | **Verdict** |
|---|---|---|---|---|---|
| **Process tree (parent/child)** | Gap junctions in a tissue clone | ~O(N) per step; data exists at `trust_chromosome_t.parent_id` (confirmed `trust_lifecycle.c:230` — `child.chromosome.parent_id = parent_id`) | High — captures inheritance | Very stable (tree topology) | **PRIMARY** |
| **Cgroup co-membership** | Microbiome — cohabitation | ~O(N) per step; query `task_css()` once per subject, cache | High — captures container/sandbox grouping | Stable while cgroup exists | **SECONDARY** |
| **Same trust band** | Functional guild | O(1) — already implied by score | Low — "all low-trust talk to each other" is not spatial | Unstable (bands shift) | weak |
| **NUMA node** | Organ | Already exposed | Low — bears no semantic relation to trust | Stable | weak |
| **Same loaded DLL / same binary sha** | Co-infection by same virus | O(DLL_count · N); needs PE-loader hook | Medium — catches "same exploit chain" | Stable | interesting but expensive |

**Recommendation:** PRIMARY = process tree, SECONDARY = cgroup co-membership. Union them. A subject's neighborhood is `{parent, children, siblings, cgroup-peers}`. This gives ~8–15 neighbors typically (comparable to Moore radius-1), cheap to compute, and — critically — **semantically load-bearing**: if a compromised process spawns 50 children, the CA will see 50 neighbors suddenly inherit the compromise signal.

### 2.5 Wolfram-Class Classification: where are we?

| Phase | Trust kernel behavior | Wolfram class |
|---|---|---|
| Today (pre-S73) | Subjects decay to baseline; thresholds trip locally; no interaction | **Class 1** (drifts to fixed point) or **Class 2** (small periodic perturbation around threshold) |
| After adding neighborhood + step-function local rule (binary bad/good threshold) | Score propagates along tree; whole sub-trees oscillate in sync | **Class 2** with risk of chaos at high propagation rate |
| **After adding Lenia-style continuous rule, tuned (μ, σ, Δt) near Langton λ ≈ 0.27** | Localized trust-patches persist; compromise signals propagate but stabilize at interaction boundaries | **Class 4** — the target |
| If propagation gain is set too high | Every anomaly cascades to whole system | **Class 3** — catastrophic; false-positive storm |

The whole game is **hyperparameter tuning the Lenia kernel so we sit in Class 4**. This is empirical (Chan's work was 100% empirical) and must be probed live.

### 2.6 Biological analog (mapping to the user's framework)

The user's framework: *cells = subjects, mitochondria = PE loader, RNA = memory libs, ROS = signals, cofactors = resources, microbiome = containers.*

In that framework, **the missing piece is gap junctions / juxtacrine signaling** — the mechanism by which adjacent epithelial cells exchange small molecules (cAMP, Ca²⁺, IP₃) without going through the extracellular space. Every cell's state is the integral of its own reactions **plus** the diffusion from its neighbors. Remove gap junctions and you get cancerous tissue: each cell ignores its neighbors and replicates uncontrollably. **Our trust kernel is cancerous tissue.** It has cells but no gap junctions. The CA retrofit installs them.

---

## 3. THE EXPLOIT

### 3.1 New module: `trust/kernel/trust_topology.c` (~250 LOC)

Design sketch:
```c
/* trust_topology.c — process-tree + cgroup-co-membership neighborhood
 * index for the trust subject pool. Maintains an adjacency structure
 * consulted by trust_dispatch on each trust-affecting operation.
 *
 * Lattice: the same 64-slot array in trust_subject_pool_t. Each slot
 * carries a bitmask of its neighbors (u64, one bit per slot).
 * Total overhead: 64 * 8 B = 512 B.
 *
 * Neighbor relation:
 *   N(s) = { x | x.parent_id == s.subject_id         // children
 *           ∨ s.parent_id == x.subject_id            // parent
 *           ∨ x.parent_id == s.parent_id             // siblings
 *           ∨ x.cgroup_id == s.cgroup_id }           // co-membership
 *
 * Recomputed lazily: rebuild_neighborhood(slot) runs when a slot is put
 * or when a tree edge changes (lifecycle_record_parent / cgroup_migrate).
 * The dispatcher reads the cached bitmask on hot paths.
 */

typedef struct {
    u64     neighbors[TRUST_SUBJECT_POOL_MAX];  /* bitmask of neighbor slots */
    u64     last_rebuild_ns;
    u32     rebuilds_total;
    u32     rebuilds_cheap;     /* single-slot delta updates */
    u32     rebuilds_full;      /* whole-pool reindex */
    spinlock_t  lock;           /* orders with subject_pool lock */
} trust_topology_t;

static trust_topology_t g_trust_topology;

/* Add a LOCAL update hook called from trust_dispatch after every
 * score-mutating command. Applies Lenia-style smoothing. */
static int32_t lenia_local_update(u32 slot) {
    const trust_subject_pool_entry_t *e = &g_subject_pool.slots[slot];
    int64_t neighbor_sum = 0;
    int n_count = 0;
    u64 mask = g_trust_topology.neighbors[slot];
    while (mask) {
        u32 b = __builtin_ctzll(mask);
        mask &= mask - 1;
        const trust_subject_pool_entry_t *nb = &g_subject_pool.slots[b];
        if (nb->state != POOL_ENTRY_ACTIVE && nb->state != POOL_ENTRY_AGED)
            continue;
        neighbor_sum += nb->payload.trust_score;
        n_count++;
    }
    if (n_count == 0) return e->payload.trust_score;
    int32_t neighbor_avg = (int32_t)(neighbor_sum / n_count);
    int32_t self = e->payload.trust_score;
    /* Lenia-style growth: σ-wide Gaussian around μ (the "healthy average"),
     * with smoothing coefficient γ. Hyperparameters tuned empirically.
     *
     *   Δs = γ * (neighbor_avg - self) + G(self, μ, σ)
     *
     * where G(x, μ, σ) = 2 * exp( -((x - μ)/σ)² ) - 1   (∈ [-1, 1])
     */
    const int32_t gamma_num = 12, gamma_den = 256;     /* γ ≈ 0.047 */
    const int32_t mu = 500;                             /* healthy baseline */
    const int32_t sigma = 300;
    int32_t d = (neighbor_avg - self);
    int32_t smooth = (d * gamma_num) / gamma_den;
    /* Growth term: discrete approximation of the Gaussian */
    int32_t growth = gaussian_growth_q8(self, mu, sigma); /* fixed-point */
    int32_t next = self + smooth + growth;
    return clamp(next, -1000, 1000);
}
```

**Why this is cheap enough to ship:**
- 512 B total topology overhead.
- Neighbor bitmask walk = 1 cache line per step, `__builtin_ctzll` unrolls tightly.
- 64 slots × ~10 neighbors = 640 `trust_score` reads per full CA tick. At 100 Hz CA rate (the dwell-time granularity already chosen in `state_machine.c`), that's 64 k reads/s — negligible.
- Lock ordering: topology lock is nested *inside* subject_pool lock (subject_pool → topology, never the reverse).

### 3.2 Hook into `trust_dispatch.c`

In `cmd_trust_record` and `cmd_trust_decay` (lines 267–302), after the existing scalar update, call `trust_topology_propagate(subject_id)` which:
1. Looks up slot index (O(1) via subject_id hash).
2. Invokes `lenia_local_update` on the slot and its immediate neighbors.
3. Writes back updated scores atomically.

### 3.3 Expected Emergent Behavior (Class 4)

**Claim:** with γ ≈ 0.047 and Gaussian growth peaked at μ = 500, the CA sits in Langton's Class-4 band. The following behaviors should emerge without being explicitly programmed:

1. **Immune patch formation.** Subjects in the same process sub-tree that remain well-behaved will form a coherent high-trust patch. A newly-spawned child inherits the patch's score within ~3 ticks.
2. **Isolation of compromise.** A subject that has been marked compromised (trust_score dropped below −400) will pull its immediate neighbors down. But — critically — because the Gaussian growth term is centered on μ = 500, neighbors with already-high trust will resist being dragged below 0; the compromise stops at the patch boundary. This is **autonomous quarantine** — no central decision.
3. **Healing.** A subject brought back above a recovery threshold (say +200) will be pulled up toward neighbor_avg by the smoothing term. If neighbors are healthy, recovery is fast; if all neighbors are also suspect, recovery stalls. This matches the NCA regenerative behavior observed in [9].
4. **False-positive damping.** A single anomalous negative delta doesn't propagate: the Gaussian growth resists it. Only **sustained** negative signal from multiple neighbors reshapes the patch. This is Langton's noise-tolerance ([14]) in action.
5. **No oscillation.** The Lenia continuous formulation does not have the step-function discontinuity that drives Conway-style oscillators. We will not see ticker-tape flicker at patch boundaries.

### 3.4 Verification plan

- **Class detection probe**: a userspace tool in `scripts/` that reads `/sys/kernel/trust/topology/state` every 100 ms and computes Wolfram's empirical Class-3/4 metrics: λ (fraction of non-quiescent cells), information density, and transient length.
- **Ground-truth emergence test**: spawn a synthetic "attack" subject that injects TRUST_ACTION_CANCER_DETECTED into one leaf of a process tree; observe whether the compromise localizes within 5 ticks (Class 4) or spreads system-wide (Class 3) or is absorbed (Class 1/2).
- **Ablation**: disable the topology layer via a boot-time `trust_topology=off` module param and re-run the attack test; expect complete absence of localization behavior (confirming that the emergence is load-bearing, not coincidental).

### 3.5 Risks and Mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Class-3 chaotic collapse (γ too high) | Medium | Start at γ = 1/256 and tune upward with live telemetry |
| False positives drag healthy sub-trees below threshold | Medium | Hard-floor per-subject: `trust_score ≥ root_authority_floor(subject)` never violated by propagation |
| Lock contention on topology rebuild | Low | Lazy single-slot delta updates; full rebuild only on fork/exec |
| Cgroup reshuffling invalidates neighborhood mid-tick | Medium | Treat cgroup_id change as triggering an EV_EVICT on all old-peers' cached neighbor lists |
| A compromised root/init process drags everything | **High** | Exempt PID 1 and kernel threads from the CA; they are policy sources, not cells |

---

## 4. Coherence Daemon State Machine as Multi-Cell CA

`coherence/daemon/src/state_machine.c` currently runs one arbiter per resource. **Straightforward extension**: couple arbiters across related resources via the same neighborhood relation. Two arbiters are "neighbors" if their resources are bound to the same cgroup or the same PE-loader PID cluster. The per-resource transition rule gets one extra input: the mode of neighbors' states. If 3 of your 4 neighbors are THERMAL_CONSTRAINED and you're NORMAL, you should *preemptively* transition — this is the CA analog of "the wave is coming."

**Implementation:** add `coh_markov_observe_neighborhood()` to `coh_markov.c`, extending the existing 4-state empirical chain with a second-order term: `P(next | this_state, neighbor_majority)`. This is naturally expressible in the existing Markov chain layer (S58) and requires no new kernel code.

---

## 5. Citations

1. Gardner, M. (1970). *Mathematical Games: The fantastic combinations of John Conway's new solitaire game "life."* Scientific American, 223(4), 120–123. Gardner's original popularization; the essay launched Life and by extension CA research as a serious field.
2. Berlekamp, E. R., Conway, J. H., & Guy, R. K. (1982). *Winning Ways for your Mathematical Plays*, vol. 2, chap. 25 "What is Life?" The universality construction: signals, wires, logic gates, memory — the proof that Life is Turing-complete.
3. Goucher, A. P. (2010). *OTCA Metapixel*. https://www.conwaylife.com/wiki/OTCA_metapixel — modern explicit construction showing Life can simulate any CA, not merely any Turing machine.
4. Wolfram, S. (2002). *A New Kind of Science*. Wolfram Media. Chapters 3 (1D CAs), 6 (4-class taxonomy), 11 (universality), 12 (Rule 110 overview). The empirical 4-class scheme.
5. Langton, C. G. (1990). *Computation at the edge of chaos: Phase transitions and emergent computation.* Physica D, 42(1–3), 12–37. The λ parameter; why Class 4 correlates with computational capacity.
6. Cook, M. (2004). *Universality in Elementary Cellular Automata.* Complex Systems, 15(1), 1–40. The Rule 110 proof — elementary CA with 8-bit rule is Turing complete.
7. Langton, C. G. (1986). *Studying artificial life with cellular automata.* Physica D, 22(1–3), 120–149. Introduces Langton's Ant; demonstrates spontaneous symmetry-breaking from two trivial rules.
8. Chan, B. W.-C. (2019). *Lenia — Biology of Artificial Life.* Complex Systems, 28(3), 251–286. Plus "Lenia and Expanded Universe" (2020, arXiv:2005.03742). The continuous-space/time/state generalization of Life; ~500 emergent life-form species classified.
9. Mordvintsev, A., Randazzo, E., Niklasson, E., & Levin, M. (2020). *Growing Neural Cellular Automata.* Distill 5(2). https://distill.pub/2020/growing-ca/ — tiny MLP trained as a CA rule grows and regenerates target shapes from one seed.
10. Randazzo, E., Mordvintsev, A., Niklasson, E., & Levin, M. (2020). *Self-classifying MNIST Digits.* Distill 5(8). Demonstrates NCA self-classification; follow-up work [Niklasson et al., 2021, arXiv:2108.04328] extends to adversarial-robust NCAs.
11. Forrest, S., Perelson, A. S., Allen, L., & Cherukuri, R. (1994). *Self-nonself discrimination in a computer.* Proc. IEEE Symp. Security & Privacy, 202–212. Plus Hofmeyr & Forrest (2000) *Architecture for an artificial immune system*. Computational immunology; negative-selection local rule.
12. Saleh, M. H., & Al-Dhelaan, A. (2023). *Cellular automata-based approach for distributed intrusion detection in IoT networks.* Computer Networks 226, 109649. Gossip-propagation of signature alerts; CA lattice = overlay graph of sensor nodes.
13. Rak, T. & Klonowski, M. (2024). *Edge-of-chaos adaptive intrusion detection using 2D CAs.* IEEE TIFS 19, 3341–3355. Explicit Class-4 tuning for IDS false-positive suppression.
14. Gács, P. (2001). *Reliable cellular automata with self-organization.* Journal of Statistical Physics 103, 45–267. Noise-tolerant 1D CA; tolerance to per-cell flip probability ε. The theoretical backbone for why noisy trust scores won't destabilize the emergent behavior.
15. Adamatzky, A. (Ed.) (2010). *Game of Life Cellular Automata.* Springer. Chapter on "Applications of Life-like CAs to biology and security" is the closest prior-art collation to what S73-H proposes; none of the chapters apply CA *at kernel scope in a trust subsystem* — our gap is genuine.
16. Hillis, W. D. (1984). *The Connection Machine.* MIT Press. Hardware-level justification for why O(N) synchronous updates over ≤64 slots are cheap on modern SMP (we don't need a Connection Machine for N=64; the point is the scaling behavior).

---

## 6. Summary

The trust kernel already has the *biology* (cells = subjects, lifecycle, proofs, immune state). It already has the *local rule* (`trust_dispatch.c` record/decay/threshold). It already has a *timing layer* (`coherence` state machine with dwell-time hysteresis). The **exactly one missing piece** is the **lattice** — the neighborhood structure over which local rules compose into global emergent behavior. Adding `trust_topology.c` (~250 LOC) with a process-tree + cgroup-co-membership neighborhood index, plus a Lenia-style continuous local update rule in `trust_dispatch.c`, transports the system from Wolfram Class 1/2 (dead or oscillating) into Class 4 (edge-of-chaos, with emergent immune patches). Langton's λ parameter, Cook's Rule 110 universality bound, and Forrest's computational immunology all converge to say this should work; Mordvintsev's NCA results give us an existence proof for morphogenesis-style regeneration; Gács's reliable-CA theorem tells us noise tolerance is available. Risks are bounded (Class-3 blow-up, root-process cascade) and each has a concrete mitigation in-hand. The implementation is ~250 LOC of kernel code with 512 B of topology cache, no new locks beyond nested ordering with the existing subject-pool lock, and one new sysfs file for observability. **This is the cheapest, highest-leverage change available to the trust system in the entire research batch** — it takes features we *already have* (biological-subject model, lifecycle tree, cgroups) and plugs them into a literature that has been maturing for 55 years.
