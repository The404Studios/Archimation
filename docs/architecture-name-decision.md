# Architecture name — decision document

**Purpose:** this document exists so the user can make the final call on
whether to rename anything in the architecture. The synthesizer-architect
(S74 post-research) concluded that the research axes do NOT require a
rename. This doc lays out the reasoning and the three candidate names, so
the user can confirm, override, or park.

**Status:** synthesizer recommendation = **KEEP existing naming**.
Justification follows. Three alternative names surveyed for prior-art
collision.

---

## 1. The existing naming

Two names are currently in use, at different levels:

| Name | Level | Source of record |
|------|-------|------------------|
| **Root of Authority (RoA)** | The mathematical/conceptual primitive: APE + chromosome + ISA + TRC + morphogen + quorum + algedonic + self-attest + invariants. The "what the kernel module actually does." | Zenodo paper (Roberts/Eli/Leelee, DOI 10.5281/zenodo.18710335), `trust/include/trust_theorems.h:5-6` |
| **ARCHWINDOWS** | The product / distribution: Arch Linux ISO + bootc image + PE runtime + AI daemon + desktop. The "what the user installs." | `profile/airootfs/etc/motd`, `README.md`, product branding (S64) |

Both names are live, both are unambiguous in their respective levels, and
neither appears in current prior art at a collision-causing frequency
(see §3 below).

---

## 2. Why not rename

The synthesis of the 10 research agents surfaced **no finding** that
makes either name indefensible. The research findings that had naming
implications:

- **RE §3.6 — rename "XY sex determination."** Recommends `conformance_quadrant`
  for the internal constant. Does NOT recommend renaming the whole
  architecture. The four-state lattice is sound; only the "XY" alphabet
  misleads biologists. **Affects a constant name, not the architecture
  name.**
- **RE §4.5 — rename `trust_meiosis()`.** Recommends
  `trust_dual_authority_bond()`. Affects a function name, not the
  architecture name. The function does something real and architecturally
  valuable; it just isn't meiosis.
- **RB §3 — "meiosis" is metaphor-only.** Same outcome as RE §4.5.
- **RJ §3.3 — biology overclaimed.** Specifically flags "biologically-
  inspired" as a teachability aid, not a technical property. This argues
  **against** rebranding the whole architecture AS a biology product
  (would make the overclaim WORSE). Retain bio vocabulary at the
  function-comment level, lean on mathematical properties at the
  architecture-claim level.

None of the 10 research reports argued for renaming "Root of Authority"
or "ARCHWINDOWS." The authorial coherence of the paper naming itself,
plus the product branding having settled in session 64, plus zero
prior-art collisions, plus zero reviewer feedback requesting a rename,
all point to: **do not rename**.

The temptation to rename comes from marketing. The case against renaming
comes from: (a) cost of rename (paper references, downstream docs, memory
files, search-indexed content); (b) loss of identity coherence between
paper and code; (c) no one has asked us to rename. The synthesizer's
judgement is that the marketing upside does not outweigh the identity-
coherence downside.

---

## 3. Three alternative names surveyed (for the user who disagrees)

If the user disagrees with §2 and wants a rename, the three candidates
ranked by precision:

### 3a. "Cybernetic Authority Kernel" (CAK)

**Precision.** HIGH. The architecture IS a cybernetic system (Beer VSM
structure, algedonic channel, observer loop, autonomy controller) AND
AN authority kernel (trust.ko mediates all authorization).

**Prior art scan.** No exact match on Google Scholar / arXiv / ACM DL /
USENIX for "Cybernetic Authority Kernel." Close misses:
- "Cybernetic Security" (general term; no specific system)
- "Authority kernel" (Microsoft Security Kernel was sometimes referred
  to this way in NT documentation; not a product name)
- Stafford Beer's "Cybersyn" (Allende-era Chilean governance system,
  1971-1973; different semantic space)

**Risks.** "Cybernetic" is an academic word; doesn't sell. A product
marketed as "CAK" sounds like a compiler (GCC, CLANG, AKKA). The
abbreviation has an awkward phoneme.

**Recommendation if selected.** Use "Cybernetic Authority Kernel" as a
subtitle, not a product name: "ARCHWINDOWS — a Cybernetic Authority
Kernel for Windows-on-Linux runtime." Keeps ARCHWINDOWS as the
brand, uses CAK as a descriptor.

### 3b. "Dynamic Capability Kernel" (DCK)

**Precision.** HIGH. Contrasts with seL4's static capabilities. Our
capabilities decay (TRC), entangle (APE), and inherit with bound (T4) —
all dynamic. The academic framing as "a dynamic extension of
capability-based protection" is defensible.

**Prior art scan.** "Dynamic capability" is a term of art in
management studies (Teece-Pisano-Shuen 1997); zero OS-literature
collision. "Capability Kernel" is generic.

**Risks.** "Dynamic capability" has a non-trivial management-literature
meaning ("the firm's ability to integrate, build, and reconfigure internal
and external competences"); Google searches would be polluted. Also, "DCK"
is an unfortunate abbreviation.

**Recommendation if selected.** Avoid. The management-literature pollution
is real and would complicate academic search.

### 3c. "Adaptive Authority Substrate" (AAS)

**Precision.** MEDIUM. "Adaptive" conveys the dynamic aspect without the
management-studies pollution. "Authority substrate" is a neutral framing
that doesn't overclaim (vs "kernel" which invites scrutiny of why it's
not in ring 0 of its own).

**Prior art scan.** Clean. No conflicts.

**Risks.** "Adaptive" is overused in cybersecurity branding (Adaptive
Shield, Adaptive Auth, Adaptive MFA). Loses distinctiveness.

**Recommendation if selected.** Third-best. Reserve in case future
positioning requires distancing from both "kernel" (if trust.ko is
refactored as a userspace module) and "cybernetic" (if Beer VSM framing
is retired for simplicity).

---

## 4. Combined ranking

If user wants a rename:

1. **Keep current.** (synthesizer recommendation) — lowest cost, zero risk
2. **Subtitle with CAK.** — preserves brand, adds technical clarity
3. **Rebrand to DCK.** — risky due to management-literature collision
4. **Rebrand to AAS.** — clean but indistinct

---

## 5. Final recommendation

**Retain "Root of Authority" (primitive) and "ARCHWINDOWS" (product).**

Update documentation in the following places to increase name-consistency:

- `docs/architecture-v2.md` — DONE (uses both names in §0-§10)
- `README.md` — verify it mentions RoA as the foundation + ARCHWINDOWS as
  the distribution
- `CLAUDE.md` — verify the "5-layer model" references Layer 0 as "RoA
  (trust.ko)" not generic "kernel"
- Paper — NO change (user-owned, already uses "Root of Authority")

If the user overrides and wants a rename, option 2 ("ARCHWINDOWS — a
Cybernetic Authority Kernel for Windows-on-Linux runtime") is the lowest-
risk way to add technical descriptor without rebranding the whole thing.

**The user decides.** This document exists to make that decision
informed, not to make it.

---

**End of name-decision document.**
