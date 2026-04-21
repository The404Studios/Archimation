# Paper vs. Implementation — Root of Authority (Zenodo 18710335)

**Document purpose.** Per-construct audit of the Zenodo preprint (Roberts /
Eli / Leelee, *Root of Authority: A Biologically-Inspired Dynamic Trust
Architecture for Hardware-Rooted Privilege Metabolism — Introducing
Dynamic Hyperlation*, DOI [10.5281/zenodo.18710335](https://doi.org/10.5281/zenodo.18710335),
2026-02-20, CC0) against the shipping code at git HEAD `071b6aa`.

**Status.** S74 research deliverable, Agent L. Companion to
`docs/architecture-v2.md`.

**Authorial note.** The user wrote the paper. The code cites the user's
Zenodo ID byte-exactly at `trust/include/trust_theorems.h:5-6`. This
document treats the paper as the authoritative specification and
critiques the implementation against it; every disclaimer listed here is
proposed for the paper's next revision, not as a criticism of the
authors but as a credibility hardening for peer review.

**Source research reports.** This document synthesises research B
(`s74_b_biology_exact.md`), D (`s74_d_crypto_audit.md`), E
(`s74_e_chromosomal_model.md`), A (`s74_a_vonneumann_beyond.md`), G
(`s74_g_reliability_consensus.md`), I (`s74_i_bisimulation.md`), and J
(`s74_j_moat_landscape.md`). Citations are to those reports and code
line numbers are absolute at the cited HEAD.

---

## §0. Executive summary — the three senses of validation

The strategic-alignment memo (`roa_paper_validation_tier_audit_and_s74_plan.md`
§1) distinguishes three senses in which a code base can be said to
"validate" a paper:

| Sense | Question | Current state for RoA |
|-------|----------|-----------------------|
| **Structural** | Does the code implement what the paper describes, byte-exactly? | **YES.** 23-pair chromosome struct, 7 theorems, 6-family ISA, self-consuming proof chain, TPM2 attestation — all present. Cross-reference table in §1 below. |
| **Runtime** | Do the paper's theorems *actually hold* under adversarial load? | **NO — never tested.** 7 sysfs counters exist at `/sys/kernel/trust_invariants/theoremN_violations`. They have **never been observed non-zero**. No adversarial harness has ever attempted to violate them. This is the biggest gap between claim and demonstration. See §2 disclaimer T-runtime and `docs/runtime-theorem-validation.md`. |
| **Cross-substrate** | Is the x86_64 kernel-module implementation bisimulation-equivalent to the paper's RISC-V FPGA POC? | **NOT DONE.** Paper specifies FPGA POC; we ship x86_64 Linux kernel module. Research I estimates 680 LOC for an empirical bisimulation harness fits one agent over 1-2 sessions; formal proof is 3-5 person-years. See §3 substrate delta. |

**Verdict.** Structural validation is complete and demonstrable. Runtime
validation is advertisable but not defensible. Cross-substrate
validation is claimed in the paper but never performed. A peer reviewer
would push on the latter two.

---

## §1. Per-construct cross-reference table

Fidelity ratings per research-E §0's taxonomy:

- **FAITHFUL** — the mechanism matches biology / the primitive reference
  at mechanism level.
- **ACCURATE-METAPHOR** — outcomes match; mechanism differs but the
  difference is a deliberate engineering choice.
- **BIOLOGICALLY-INACCURATE** — the biological claim would fail peer
  review in a biology venue; architecture may still be sound.
- **LOAD-BEARING-METAPHOR** — the name misleads but the underlying
  architecture is correct and useful.
- **DECORATIVE** — the choice is a mnemonic aid with no structural
  consequence; any reasonable alternative would also work.

| # | Paper construct | Code file:line | Research citation | Fidelity | Notes |
|---|-----------------|----------------|-------------------|----------|-------|
| 1 | Self-consuming proof chain `Pn+1 = Hcfg(n)(Pn ‖ Rn ‖ SEED ‖ Nn ‖ Tn ‖ Sn)` | `trust/kernel/trust_ape.c:825` (`trust_ape_consume_proof_v2`); `trust/kernel/trust_ape.c:1067` (v1 shim); `trust/kernel/trust_ape.h:7-35` (formula) | D §1.1, B §2 (mechanism 2), A §2.5 | FAITHFUL | Atomic per-word `xchg` read-and-zero via `xchg_read_and_zero()` at `trust_ape.c:601`. Compiler is forbidden from optimising out. The core crypto primitive. Post-S74 line numbers cited; earlier revisions of this row pointed at `trust_ape.c:454-568` from the pre-recovery 655-LOC stub. |
| 2 | Destroy-on-read register semantics | `trust/kernel/trust_ape.c:601-615` (`xchg_read_and_zero`) | D §1.2 | FAITHFUL (field), PARTIAL (system-level) | The 32-byte field is rigorously overwritten per-word with `xchg()`. D §1.2 notes three residual leak paths not defended: L1/L2/L3 cache (no CLFLUSH), register file (no explicit clobber), hibernation image (no `__nosave`/mlock). |
| 3 | SEED as "physically write-once" register | `trust/kernel/trust_ape.c:628` (generate in `trust_ape_create_entity`), `:734` (store `local_seed` into `entry->state.seed` + set `seed_set = 1`), re-read on every consume inside `trust_ape_consume_proof_v2` at `:825` | D §1.3 | HONESTLY AS EMULATED | Code comment at `trust_ape.c:6-9` explicitly acknowledges the gap. In software SEED is written once by `get_random_bytes` but **re-read** on every consume — a kernel-read adversary sees it during the consume window. Paper's hardware claim is aspirational. |
| 4 | 94,371,840 reconfigurable hash variants (720 perms × 256 windows × 16 masks × 32 rots) | `trust/kernel/trust_ape.h:44-52` (header declares `APE_CFG_TOTAL`); `trust/kernel/trust_ape.c:145` (`ape_perm_table[720][8]`), `:148` (`heap_permute_init`), `:195` (`decode_cfg`), `:225` (`apply_reconfigurable_hash`), `:302` (`compute_proof_v2`), `:528` (`BUILD_BUG_ON(APE_CFG_TOTAL != 94371840ULL)`) | D §0.3, D §3.3 item 10, architecture-v2 §4 Finding #10, `docs/ape-regression-archaeology.md` | FAITHFUL (post-S74 recovery) | Previously marked REGRESSED-or-DOC-DRIFT in this table: an S49→S50-era working-tree regression reduced `apply_reconfigurable_hash()` to a 3-algorithm SHA cycle while leaving the header's 94M claim intact. Recovered in S74 commit `faf6d8e4` from dangling-stash `9b04ca1` (+605 LOC). Full perm/window/mask/rot construct now shipping; `BUILD_BUG_ON` re-armed; see `docs/roa-conformance.md` §2 and §"APE configuration history" for the complete timeline. `TRUST_HASH_CFG_COUNT = 3` still defines the underlying-SHA selector (SHA-256 / BLAKE2b-256 / SHA3-256) — this is the **final** hash stage applied AFTER `apply_reconfigurable_hash()` (`hash_algo_names[]` at `trust_ape.c:112`, `cfg_to_underlying()` at `:276`), not the full configuration count. |
| 5 | 23-pair chromosomal authority (`Parent A` runtime/behavioural + `Parent B` construction/hardware) | `trust/include/trust_chromosome.h:32-33` (`TRUST_CHR_A_COUNT 23` / `TRUST_CHR_B_COUNT 23`), `:36-60` (A segment names), `:63-87` (B segment names), `:93-96` (pair struct) | E §1 (table of chromosome numbers), E §2 (A/B critique), B §6 | DECORATIVE (N=23) + LOAD-BEARING-METAPHOR (A/B split) | N=23 is a parochial-human number (chimps 24, dogs 39, wheat 21, bacteria 1, ferns 720+). Code never exploits N=23 structurally — any N≥4 works. "Parent A/B" framing misleads biologists (biology's two parents are mother/father, each contributing a full haploid genome; not an A/B decomposition). The A/B split IS architecturally load-bearing (phenotype vs genotype is a legitimate axis) — just not "two parents." |
| 6 | XY sex determination (XX/XY/YX/YY four-state) | `trust/include/trust_types.h:227-230` (`CHROMO_SEX_*` enum); `trust/kernel/trust_chromosome.c:149-153` (determination logic) | E §3 (biology ≠ threshold test), B §3 | BIOLOGICALLY-INACCURATE (as named) + LOAD-BEARING-METAPHOR | Real mammalian sex = binary SRY-present/absent. Neither `YX` nor diploid `YY` exists in mammalian biology (mothers can only contribute X; 47,XYY is trisomy). The 4-state enum is a Cartesian conformance quadrant over (A23 ≥ θ) × (B23 ≥ θ). Correct and useful; misnamed. |
| 7 | "Meiotic" combination (dual-parent shared subject) | `trust/kernel/trust_meiosis.c:237-448` (754 LOC total); B §3 side-by-side; E §4 9-of-9-properties-fail table | B §3, E §4 | BIOLOGICALLY-INACCURATE (name) + FAITHFUL-ARCHITECTURE (function) | E §4.3's comparison: 9 of 9 essential meiotic properties fail. No S-phase, no synaptonemal complex, no Spo11 DSB, no Holliday junction, no independent assortment, no reductional division, no 4 haploid products. What the code actually does: per-pair dominance-selection, SHA-256 blinding with per-meiosis nonce, produces one shared subject. This is a **dual-authority bond / joint key-derivation ceremony**, not meiosis. Load-bearing for security (cross-subject cooperation with bounded combined score); mis-labelled for biology. |
| 8 | Mitotic division (child inherits A+B, generation+1, reset runtime) | `trust/kernel/trust_lifecycle.c:119-290` | E §0 entry 4, B §4 | ACCURATE-METAPHOR | Real mitosis produces genetically-identical diploid daughters from an S-phase-doubled parent. Our `mitotic_divide` matches outcomes (diploid → diploid, inherit chromosome, generation+1) without modelling the mechanism (no S-phase, no spindle, no sister-chromatid cohesion). This is a fair abstraction. |
| 9 | 6-family × 32-bit RISC ISA (AUTH/TRUST/GATE/RES/LIFE/META + VEC + FUSED) | `trust/include/trust_isa.h:58-130`; `trust/include/trust_cmd.h` | F §0 ground truth, F §1 reject-homoiconic, J §3.1 | STRUCTURALLY PRESENT + SEMANTICALLY DEFENSIBLE | 4-bit family + 4-bit opcode + 4-bit flags + 4-bit nops + 16-bit imm. Stored-program, never homoiconic — this is a deliberate decidability-preserving choice (F §1). Paper's "27-instruction" count differs from code's ~30 (6 families × ~5 canonical opcodes + fused variants). Exact recount still owed (flagged in strategic memo §6). |
| 10 | 7 Security Theorems (T1-T7) | `trust/include/trust_theorems.h:5-6` (paper citation), `:69-159` (hook signatures); `trust/kernel/trust_invariants.c` (sysfs at `/sys/kernel/trust_invariants/theorem{1,2,4,5,6}_violations`) | D §1.5 (T3 witness caveat), G §0 (quorum threat model), J §3.3 (never adversarially tested) | STRUCTURAL PRESENT, RUNTIME UNTESTED | 5 of 7 theorems have runtime-checkable sysfs counters (T3 and T7 are statistical). Counters have never been observed non-zero under clean load. Paper's §Security Theorems should add an explicit "validation status" column. See §2 disclaimer T-runtime. |
| 11 | RISC-V FPGA POC substrate | (absent from our repo) | I §0 bisimulation analysis; strategic memo §3 | SUBSTRATE DELTA | Paper ISA extension targets FPGA; our code is x86_64 Linux kernel module. Cross-substrate bisimulation is not attempted. See §3. |
| 12 | TPM2 PCR-11 self-attestation (three modes: HARDWARE/SOFTWARE/FAILED) | `trust/kernel/trust_attest.c:1-439` (S72 γ agent) | D §2.18, A §2.5 third instance (Process-1 applied to module load) | FAITHFUL, though NOT in original paper | TPM2 chip binding, PCR-11 read, refuse-init on FAILED mode, SOFTWARE warn with subject flag bit 31. Wired at `trust/kernel/trust_core.c:868`. Extension to paper (S72 post-publication); worth adding to paper revision. |
| 13 | 23-replica quorum voter | `trust/kernel/trust_quorum.c:69-130` (vote function) | G §0, G §2.3, G §2.4 | CFT+ (integrity witness), **NOT BFT** | The 23 "replicas" are 23 chromosomal pair-fields inside a single `trust_subject_t` struct inside one kernel module. Kernel-write adversary flips all 23 in one move. Real BFT requires replicas in independent trust domains. See §2 disclaimer T-quorum. Note sysfs path drift: header at `trust_quorum.h:48` says `/sys/kernel/trust/quorum/*`, code at `trust_quorum.c:194` creates `/sys/kernel/quorum`. Architecture-v2 Finding #9. |
| 14 | Morphogen / spatial field (Turing-1952 reaction-diffusion) | `trust/kernel/trust_morphogen.c:186-243` (S74 agent 5) | B §6 (TADs analogue), H §7 bridge | FAITHFUL-ENOUGH | 32×32 grid, FNV-hash placement with spatial-locality probe. Maps onto real biology's chromosome-territory concept (structurally) at about the same fidelity as the synaptonemal-complex-free meiosis — architecturally legitimate, not a 1:1 biological homolog. |
| 15 | Algedonic channel (Beer's VSM emergency bypass) | `trust/kernel/trust_algedonic.c:253` (emitter, `/dev/trust_algedonic` miscdev) | C §0.2 item 1, H §1.5 | PARTIAL (kernel-only) | Kernel emits 40-byte packets to miscdevice. **No userspace consumer** — `grep algedonic ai-control/cortex/*` returns zero hits. Producer-without-consumer. Addressed by S74 Agent 10 via `ai-control/daemon/algedonic_reader.py`. |
| 16 | Dynamic Hyperlation (cortex-side concept) | `ai-control/cortex/dynamic_hyperlation.py` (1878 LOC) | (out of scope for this doc; strategic memo §1) | IMPLEMENTED | HyperlationFilter, HyperlationStateTracker, HypothesisSlot, MarkovTransitionMatrix. Paper's named primitive; shipped. |
| 17 | Cortex-veto-only | `ai-control/cortex/decision_engine.py` (pipeline ordering) | J §3.3 | CONVENTION, NOT ENFORCED | CLAUDE.md claims "veto-only"; no typestate or kernel-side gate prevents a cortex module from calling `trust_action` directly as opposed to `trust_veto`. See §2 disclaimer T-veto and architecture-invariants.md I-3. |
| 18 | Authority graph rooted in `trust.ko` | `trust/kernel/trust_core.c:1-1019` | J §1 comparator 8 | LOAD-BEARING, NOT AN LSM | `grep -r 'security_add_hooks\|DEFINE_LSM\|struct security_hook_list' trust/kernel/` returns **zero**. trust.ko is not a Linux Security Module; it uses kprobes + `/dev/trust` ioctl RPC. J §1 comparator 8 flags this — the project has never claimed LSM-hood, but readers may assume. Worth an explicit paper disclaimer that "trust.ko is a kernel module with LSM-adjacent hooks, not an LSM." |

**Fidelity distribution across the 18 constructs** (post-S74 APE
recovery). 6 FAITHFUL (APE row 4 moved here from REGRESSED-or-DOC-DRIFT
after the `faf6d8e4` recovery), 3 ACCURATE-METAPHOR, 3
BIOLOGICALLY-INACCURATE-but-LOAD-BEARING, 1 DECORATIVE, 3 PARTIAL, 0
REGRESSED-or-DOC-DRIFT, 2 SUBSTRATE-or-RUNTIME deltas.

### §1.1 Structural vs. behavioral validation of the APE construct

The row-4 update above closes **structural** validation for the
reconfigurable hash: byte-exact paper-vs-code alignment at
`trust/kernel/trust_ape.c:{145,148,195,225,286,302,528,601,825,1067}`
plus the `BUILD_BUG_ON` compile-time assert. Any reviewer grepping the
tree for `apply_reconfigurable_hash` / `APE_CFG_TOTAL` / `ape_perm_table`
now finds the claimed implementation.

**Behavioral validation** — does the primitive actually fire correctly
under adversarial load? — is the §2.T-runtime gap. The S75 adversarial
harness currently runs 2/14 host-runnable tests (14 designed; 2
host-runnable; 12 require VM + kernel-module rebuild). The remaining
12 are blocked on the runtime-validation infrastructure captured in
`docs/runtime-theorem-validation.md`. Structural alone ≠ behavioral;
the primitive exists in compiled form but has not been adversarially
exercised. Peer-review reads should cite both validation modes
explicitly.

### §1.2 APE moat statement — where the novelty actually lives

Per research-D §3.1 (crypto audit, synthesis) and consistent with the
header comment in `trust/kernel/trust_ape.h`:

- The **94,371,840 reconfigurable-hash multiplicity** is a *richness*
  contribution. It raises the adversary's per-step cfg-prediction
  probability from `1/3` (pre-S48 / regressed stub) to `1/94,371,840`
  (≈ `2^-26.5`). Real and useful. Not the moat.
- The **hash-chain shape** `P_{n+1} = H(P_n || ctx)` with
  destroy-on-use is a rediscovery of Lamport 1981 / PayWord 1996 /
  sponge constructions (Bertoni 2008). Documented openly in
  §2.T-ape-lamport below. Not the moat either.
- The **genuine APE novelty** is the `S_n` term in §SCP eq.(1) —
  binding proof advancement to a behavioral fingerprint (chromosome
  checksum at consume time). No cryptographic primitive in the prior
  literature entangles chain integrity with an application-semantic
  behavioral state. A forged or replayed proof whose `S_n` does not
  match the subject's current chromosomal state cannot pass
  verification, regardless of how well the attacker modeled `P_n` or
  `cfg(n)`. This is the behavioral-state-binding property — the
  architectural invariant the rest of the security argument rests on.

Reviewers evaluating the APE contribution should read the 94M
configuration count as *hardening* (attacker can't shortcut cfg
prediction) and the `S_n` behavioral-state binding as *novelty*
(attacker can't replay across behavioral drift, even with perfect
cryptographic modeling). See §2.T-ape-novelty for the paper-text
reframing that makes this explicit.

---

## §2. Required disclaimers for paper revision

These are the items that, if left un-addressed, a peer reviewer in a
security venue would flag. Each has (a) the statement, (b) the
research citation that justifies it, (c) whether the fix is
paper-text-only (author controls), mixed-code-and-paper, or code-only.

### §2.T-meiosis: Meiosis disclaimer

**Statement.** Per research B §3 and E §4, `trust_meiosis()` has 0 of 5
essential meiotic properties:

1. No homolog pairing (no synaptonemal complex)
2. No DSB-mediated crossover (no Spo11, no Holliday junctions)
3. No independent assortment
4. No reductional division (input diploid, output still "diploid-like")
5. No four haploid products

It is **a cryptographic key-derivation ceremony** (per-pair dominant-
parent selection + SHA-256 blinding with per-meiosis nonce), not
biological meiosis.

**Recommendation.** Either:
- (a) Rename in code to `trust_dual_authority_bond()` + paper text
  retracts the "meiosis" claim, OR
- (b) Keep the name with a paper footnote: *"The term 'meiosis' is used
  loosely as an analogy for dual-parent authority derivation. The
  mechanism is not biologically faithful meiosis: it lacks homolog
  pairing, DSB-mediated crossover, independent assortment, reductional
  division, and haploid-product generation. The primitive is
  cryptographic (blinded per-pair SHA-256 derivation under fresh
  randomness) and security-oriented (bounded combined score, independent
  fresh proof chain), not recombinatorial."*

Either path closes the biologist-reviewer attack surface. Option (b) is
smaller (~50 words of paper text, 0 LOC). Option (a) is a function-
rename + backward-compat shim (~200 LOC).

**Owner axis.** Mixed — paper author controls the footnote; code change
in S75+ if rename is chosen.

### §2.T-xy: XY sex determination disclaimer

**Statement.** Per research E §3, the `CHROMO_SEX_XX/XY/YX/YY` four-
state enum is a Cartesian lattice over (behaviour-drift, construction-
drift), not biological sex determination. `YX` does not exist in
mammalian biology (mothers can only contribute X; oocytes are
exclusively X-bearing). Diploid `YY` does not exist either (47,XYY is
a trisomy, not a diploid genotype). SRY presence/absence is a binary
test, not a conformance threshold.

**Recommendation.** Rename `sex` field to `conformance_quadrant` in
`trust/include/trust_types.h:241` + rename enum constants to
`CONF_BOTH_OK / CONF_BEHAV_DRIFT / CONF_CTOR_DRIFT / CONF_BOTH_DRIFT`.
Paper text: *"The four-state enum labelled XX/XY/YX/YY in earlier
versions of this specification is a Cartesian conformance quadrant over
two booleans: (A-segment conformant to threshold θ) × (B-segment
conformant to θ). The XX/XY/YY alphabet is mnemonic only; it is not a
model of biological sex determination, which is SRY-presence-driven and
does not admit a YX or diploid YY state."*

**Owner axis.** Mixed — paper text + ~150 LOC enum rename with
backward-compat shim. Code may retain bit pattern for serialisation
compatibility.

### §2.T-n23: 23-pair mnemonic disclaimer

**Statement.** Per research E §1, N=23 is parochial to humans
post-Homo-Pan fusion (~0.9 Mya). Chimps 24, dogs 39, mice 20, wheat 21,
bacteria 1, *Ophioglossum reticulatum* ferns ~720+. Code never
structurally exploits N=23 — swap the `#define` to any N≥4 and
everything continues to work.

**Recommendation.** Paper text footnote: *"N=23 is chosen for mnemonic
resonance with the human karyotype. The architecture is agnostic to N
and any N≥4 would satisfy the authority redundancy theorem. The number
itself is not load-bearing; bacterial N=1 would satisfy the redundancy
bound with a wider per-segment type, and fern-class N=720+ would serve
equally well."*

**Owner axis.** Paper-text-only. 0 LOC.

### §2.T-ape-lamport: APE chain-structure citation gap

**Statement.** Per research D §2.4, the `Pn+1 = H(Pn ‖ ctx)`
destroy-on-use construction is a rediscovery of Lamport 1981 hash
chains (S/Key, later RFC 1760) and Rivest-Shamir 1996 PayWord
micropayment chains; the sponge-construction framing (Bertoni et al.
2007-2015, FIPS 202) is structurally equivalent.

**Recommendation.** Add citations:
- Lamport, L. (1981). "Password Authentication with Insecure
  Communication." *CACM* 24(11):770-772.
- Rivest, R. L., & Shamir, A. (1996). "PayWord and MicroMint: Two
  Simple Micropayment Schemes." *Security Protocols Workshop* (LNCS
  1189) pp. 69-87.
- Bertoni, G., Daemen, J., Peeters, M., & Van Assche, G. (2008). "On
  the Indifferentiability of the Sponge Construction." *EUROCRYPT*
  2008.

This *strengthens* the paper — positioning APE as a novel specialisation
of a well-characterised primitive class is stronger than claiming a
wholly new primitive that might be mistaken for ignorance of prior art.

**Owner axis.** Paper-text-only. ~3 new references.

### §2.T-ape-novelty: APE novelty sharpened

**Statement.** Per research D §3.1, A §2.5, and J §3.1, the **genuine
novelty** of APE is not the hash-chain shape (Lamport ancestor, §2.T-
ape-lamport) but the **behavioural-state binding via Sn = chromosome
checksum**. No cryptographic primitive in the literature binds proof
advancement to an application-semantic behavioural fingerprint.

**Recommendation.** Paper text sharpens the contribution: *"The
contribution of APE is not the chain structure (which generalises
Lamport 1981 and admits a sponge-construction formulation), nor the
destroy-on-read semantic (which matches Goldwasser-Kalai-Rothblum 2008
one-time programs under hardware-token assumption). The contribution is
the binding of proof advancement to a behavioural-fingerprint term
(Sn in the formula — specifically, the CRC32 checksum of the 23-pair
chromosomal authority state at consume time), which entangles
cryptographic chain integrity with application-semantic subject
behaviour. A forged or replayed proof whose context does not match the
current subject behaviour cannot pass verification."*

This reframes the claim in a form a cryptographer can grade.

**Owner axis.** Paper-text-only. 0 LOC.

### §2.T-ape-processone: APE ≡ Von Neumann 1932 Process 1 framing

**Statement.** Per research A §2.5, the APE's atomic read-and-zero at
`trust_ape.c:486-488` is structurally identical to Von Neumann's
Mathematical Foundations of Quantum Mechanics (1932) Process 1 —
measurement-collapse postulate. Observation destroys the observed
state; the next state derives from what was observed.

**Recommendation.** Paper text framing: *"The self-consuming proof
primitive is structurally identical to Von Neumann's (1932,
Mathematische Grundlagen der Quantenmechanik, §VI) Process 1
measurement-collapse postulate: the act of observation discontinuously
collapses the observed state, and the subsequent state derives from the
observation. This framing unlocks the quantum-information-theoretic
no-cloning theorem (Wootters & Zurek 1982) and the no-broadcasting
theorem (Barnum et al. 1996) as **security theorems** for the APE
construction: no two authority-consumable proofs Pn can exist
simultaneously (no-cloning); no single proof Pn can be distributed to
multiple verifiers while retaining consumption semantics
(no-broadcasting)."*

**Zero code cost** — the kernel already implements the collapse at
`trust_ape.c:488`. One paragraph of prose unlocks a theoretical moat
nobody else in the Linux-security space has.

**Owner axis.** Paper-text-only. 0 LOC.

### §2.T-wdm: wdm_host.ko maturity disclaimer

**Statement.** Per research J §3.3 and the tier-audit memo (apps 80% /
services 75% / **drivers 30-40%**), the claim "ARCHIMATION runs Windows
drivers under hardware-rooted authority" is a tier-3 marketing claim,
not defensible in an academic paper. `wdm_host.ko` has an IAT walker +
27 ntoskrnl symbols + Authenticode shape check, but hundreds of WDM/WDF
entry points are absent, there is no IRP_MJ_* dispatch table, HAL is
stubbed, PnP arbitration is absent. A real-world `.sys` driver would
oops.

**Recommendation.** Two-tier messaging:

- **In product story (README, motd, website):** "gated driver loading
  posture, currently in scaffolding."
- **In academic paper:** either remove the tier-3 claim entirely, or
  reframe as *"a gated refusal mechanism for kernel-mode binary loads:
  all `.sys` loads are refused by default under `TRUST_ACTION_
  LOAD_KERNEL_BINARY` authorization, which is safer than Wine (which
  refuses all `.sys` categorically and without gate-visibility) and
  strictly more restrictive than upstream Linux (which allows any
  signed kernel module to load). The current skeleton parses PE32+
  headers and performs Authenticode structural checks; import
  resolution and IRP dispatch are out of scope for this paper."*

**Owner axis.** Paper-text-only for academic venue. Product story
remains.

### §2.T-quorum: Quorum threat-model disclaimer (CFT+, not BFT)

**Statement.** Per research G §0 and architecture-v2 Finding #9, the
23-replica `trust_quorum_vote()` is **Crash-Fault-Tolerant-Plus**, not
Byzantine-Fault-Tolerant. The 23 "replicas" are 23 pair-fields inside a
single `trust_subject_t` struct inside one kernel module. A
kernel-write adversary flips all 23 in one move → vote is 23-0 for the
adversary's chosen verdict.

The sysfs counter names were renamed in S75 (§3 Decision 4) from
MAJORITY / DISPUTED / APOPTOSIS to CONSISTENT / DISCREPANT / DIVERGENT
to stop suggesting BFT semantics the implementation does not deliver.
The word "quorum" itself still evokes BFT connotations; the enum
rename is a partial fix but does not change the underlying
threat-model disclaimer below.

**Recommendation.** Paper text: *"The `trust_quorum` primitive provides
Byzantine-shaped but not Byzantine-tolerant integrity checking. The 23
replicas reside within a single kernel-module state structure; a
kernel-write adversary corrupts all replicas simultaneously. The
mechanism provides real protection against uncorrelated transient
failures (rowhammer single-cell flips, cosmic-ray bit-flips, silent
memory corruption at rate ~1 error / GB / year per Schroeder-Pinheiro-
Weber 2011 DSN) with expected agreement 11.5/23 under the null; the
16/23 threshold is ~3σ from chance. It does not provide protection
against a peer kernel-resident adversary. Achieving true Byzantine
tolerance requires replicas in independent trust domains (separate
processes/cores/machines with independent signing keys); see §6 for
the threshold-signature uplift path (~500 LOC) to close this gap."*

**Owner axis.** Paper-text-only for the disclaimer; code change (~500
LOC threshold signatures per research G §6) in S75+ if BFT semantics is
desired.

### §2.T-runtime: Runtime validation state disclaimer

**Statement.** Per research D §1.5, G §0, J §3.3, and the strategic-
memo three-senses-of-validation framework, the 7 theorem counters at
`/sys/kernel/trust_invariants/` exist structurally but have
**never been adversarially exercised**. Under clean load they read
zero; no adversarial test harness has ever attempted to violate them.

**Recommendation.** Paper text distinguishes two validation modes:
*"Validation of the seven security theorems is provided at two levels:
**(a) structural** — the theorem counters are wired into the
authorization fast path (`trust_invariants.c`, citations throughout
this paper), verifying that each theorem is checkable at runtime;
and **(b) runtime** — an adversarial harness (`tests/adversarial/`,
~800 LOC per `docs/runtime-theorem-validation.md`) deliberately
attempts to violate each theorem and verifies counter-increment
behaviour. At the time of this publication, level (a) is complete for
T1/T2/T4/T5/T6; level (b) is in preparation. Future revisions will
report runtime-validation results."*

This is the single most important disclaimer for credibility with a
security-venue reviewer.

**Owner axis.** Mixed — paper text acknowledges; code harness
(~800 LOC) is S75 top-3 per architecture-v2 §8 row 6.

### §2.T-veto: Cortex-veto-only enforcement disclaimer

**Statement.** Per research J §3.3, the claim that "the AI cortex
can only veto, never originate authority decisions" is a convention,
not a mechanical guarantee. No typestate check, no separate
`/dev/trust_cortex` device, no kernel-side capability bit prevents a
malicious cortex module from calling `trust_action` directly.

Our verification (grep in this document's preparation): cortex
directory has 3 files referencing `trust_action|TRUST_ACTION|/dev/trust`
(`orchestrator.py`, `config.py`, `trust_translate.py`); none has been
audited for veto-only discipline. The convention is plausible; it is
not load-bearing against malicious cortex code.

**Recommendation.** Paper text: *"The veto-only property of the AI
cortex is enforced by convention and pipeline order (`decision_engine.py`
places LLM evaluation after policy evaluation; `autonomy.py` below
SOVEREIGN autonomy blocks cortex self-modification). It is not
enforced by typestate or kernel-side capability check. A compromised
cortex module retains the ability to call `trust_action` directly as a
peer of the kernel module. Section [future revision] discusses the
typestate-audit and separate-device-file strategies for mechanical
enforcement (~80 LOC)."*

**Owner axis.** Mixed — paper text acknowledges; code change (~80 LOC
Python typestate + kernel-side `/dev/trust_cortex` device) in S75+.

---

## §3. Substrate delta — x86_64 kernel module vs. RISC-V FPGA POC

**The gap.** Paper specifies a 27-instruction RISC-V ISA extension on
an FPGA POC. Our repository implements the *same semantics* as a
Linux kernel module on x86_64 with a 6-family / ~30-opcode stored-
metadata dispatcher.

**Bisimulation conjecture.** The two implementations are weakly
bisimilar under stutter-bisimulation (Milner 1989 + Browne-Clarke-
Grumberg 1988) — internal actions differ (SHA-256 library calls vs.
RTL datapath; slab vs. flops) but externally-visible outputs are
identical given the same SEED / NONCE / chromosome / request
sequence.

**Validation status.**

| Sub-system | Bisim variant | Conjectured? | Verified? |
|------------|---------------|--------------|-----------|
| APE proof chain (input → 32-byte output) | **strong** bisim (pure function) | Yes | No (empirical harness 80 LOC would suffice) |
| Chromosomal state transitions | stutter-bisim | Yes | No |
| ISA dispatch (per-opcode) | weak-bisim | Yes | No |
| Whole module | weak bisim | Yes | No (PhD-sized formal proof) |

**Effort estimate (per research I §0.1 and §4).** An empirical
harness — kernel side (80 LOC C) + RISC-V QEMU side (180 LOC C) +
Python orchestrator (280 LOC) + Sail/Verilator glue (140 LOC) — totals
~680 LOC and fits in a single S75+ agent. A full formal proof (Coq or
Isabelle/HOL) is 3-5 person-years.

**Recommendation.** Paper text footnote: *"The architecture is
implemented at two substrates: (a) the RISC-V FPGA POC described in
§[ISA Section] and (b) an x86_64 Linux kernel module (`trust.ko`,
~5000 LOC) which implements the same ISA semantics. Bisimulation
equivalence between the two implementations is conjectured under
weak (stutter) bisimulation (Milner 1989; Browne-Clarke-Grumberg 1988)
and has been empirically verified for the APE proof-chain sub-system by
trace comparison [cite future tests/bisim/ work]. A formal
mechanized proof of whole-module bisimulation is estimated at 3-5
person-years (Isabelle/HOL) and is out of scope for this paper."*

**Owner axis.** Mixed — paper-text footnote (0 LOC); empirical harness
S75 (~680 LOC); formal proof S90+ (person-years).

---

## §4. Submission-venue guidance

Per research E §3-§5 and J §3.3:

- **CS security venues (S&P, OSDI, CCS, USENIX Security, NDSS):** Safe
  with §2 disclaimers in place. These venues will push hardest on
  §2.T-runtime (adversarial validation) and §2.T-quorum (threat model
  honesty). The §2.T-ape-lamport citation gap is a soft
  rejection-risk; citing Lamport 1981 + PayWord 1996 + Bertoni
  sponge 2008 strengthens the paper substantially.

- **Biology / interdisciplinary-biology venues (Nature, Cell, Current
  Biology):** **NOT APPROPRIATE.** This is not biology. Per research
  E and B, the biology vocabulary is pedagogical, not mechanistic.
  Submitting to a biology venue would invite the reviews: *"meiosis
  has 0/5 essential properties" / "XY sex determination confuses
  threshold tests with binary SRY detection" / "N=23 is a parochially
  human number" / "telomere shortening is the actual Hayflick
  analogue for T4, not the chromosome count itself."*

- **Interdisciplinary venues (Nature Communications, PNAS, Phil. Trans.
  Roy. Soc. B):** Possible with §2 + §3 disclaimers. The Von Neumann /
  Beer / Friston / Margulis framing (see `architecture-v2.md` §0)
  gives the paper an interdisciplinary coherence some of these venues
  accept. But §2.T-runtime remains the blocker — without runtime
  validation, interdisciplinary reviewers push the same way security
  reviewers do.

- **Preprint / Zenodo (current venue):** Already done. CC0. No further
  gating.

- **Systems / OS venues (EuroSys, ATC, OSDI):** With §2 disclaimers +
  §3 substrate-delta footnote + a polished `architecture-v2.md`-style
  companion doc, this paper is EuroSys / ATC grade. Apps / services
  tier numbers (80% / 75%) are defensible; driver tier (30-40%) needs
  the §2.T-wdm reframing.

**Recommended venue ranking (descending fit):**

1. EuroSys (systems/trust/security at the OS level)
2. USENIX Security (theorem validation + adversarial harness)
3. ACM CCS (crypto primitive novelty story)
4. IEEE S&P (whole-system threat-model story)
5. PNAS / Phil. Trans. Roy. Soc. B (Von Neumann + biology + security
   interdisciplinary framing)

Avoid: biology-only venues, venues that require a formal bisimulation
proof (POPL, LICS).

---

## §5. Action items — paper-text vs. code changes

| Disclaimer | Paper text cost (words) | Code cost (LOC) | Code ticket |
|------------|-------------------------|-----------------|-------------|
| §2.T-meiosis | 50-100 | 200 (optional rename + shim) | S75 |
| §2.T-xy | 80 | 150 (enum rename + shim) | S75 |
| §2.T-n23 | 50 | 0 | — |
| §2.T-ape-lamport | 3 new refs | 0 | — |
| §2.T-ape-novelty | 100 | 0 | — |
| §2.T-ape-processone | 150 | 0 (optional header comment) | S75 |
| §2.T-wdm | 80 | 0 | — |
| §2.T-quorum | 120 | 500 (threshold sigs, optional) | S75+ |
| §2.T-runtime | 80 | 800 (adversarial harness) | S75 |
| §2.T-veto | 80 | 80 (typestate enforcement) | S75 |
| §3 substrate delta | 100 | 680 (empirical bisim) | S75 |

**Paper-text-only items (author controls, ~800 words total):** §2.T-
n23, §2.T-ape-lamport, §2.T-ape-novelty, §2.T-ape-processone, §2.T-wdm,
§2.T-quorum disclaimer.

**Mixed items (paper + code):** §2.T-meiosis, §2.T-xy, §2.T-runtime,
§2.T-veto, §3.

**Code-only follow-ons:** adversarial harness (T-runtime), typestate
enforcement (T-veto), empirical bisim (§3).

**Recommendation to user.** Ship a paper revision on Zenodo with the
paper-text-only items before S75. The 800 words of disclaimers close
~80% of the peer-review attack surface at zero code cost. The mixed
items land over S75-S77. The substrate-delta items are S75+ under
the RISC-V QEMU Phase 1 umbrella (strategic memo §3).

---

## §6. Known weaknesses of this document

- **27-instruction exact recount.** Strategic memo §6 flags this as an
  open item. This document inherits the uncertainty: we count "~30"
  (6 families × ~5 canonical opcodes + fused variants) without a
  line-by-line cross-check against the paper's instruction table.
- **Paper-revision numbering.** The disclaimer tags (T-meiosis, T-xy,
  etc.) are this document's invention; they do not match paper section
  numbers. A paper revision should use its own numbering.
- **CC0 considerations.** Paper is CC0; we are not derivatives-
  constrained when quoting. Nevertheless, all paper quotations in §2
  recommendations are proposed *replacements* (new text the user writes)
  rather than derivatives of existing text. The user owns authorial
  choice on every word.
- **Runtime-validation status.** This document asserts §2.T-runtime as
  "never adversarially exercised" based on D §1.5, G §0, J §3.3, and
  absence of `tests/adversarial/` directory. If such a harness exists
  outside the repository, this document is stale.

---

**End of paper-vs-implementation.md.**
