# Architecture name — decision document

**FINAL NAME: Archimation.** Decided by user prior to S74 synthesis;
runtime branding was partially migrated already (WBEM, fastfetch, systemd-
boot). The synthesizer-architect's KEEP recommendation (previous version of
this doc, dated S74 post-research) was based on incomplete information and
is **superseded**. This document is kept as a historical record of the
prior-art survey and the decision trail.

**Status:** decision closed. Name is Archimation.

---

## 1. The name

Two names are in use at different levels:

| Name | Level | Source of record |
|------|-------|------------------|
| **Root of Authority (RoA)** | The mathematical/conceptual primitive: APE + chromosome + ISA + TRC + morphogen + quorum + algedonic + self-attest + invariants. The "what the kernel module actually does." | Zenodo paper (Roberts/Eli/Leelee, DOI 10.5281/zenodo.18710335), `trust/include/trust_theorems.h:5-6` |
| **Archimation** | The product / distribution: Arch Linux ISO + bootc image + PE runtime + AI daemon + desktop. The "what the user installs." | `profile/airootfs/etc/motd`, `README.md`, product branding |

Both names are live, both are unambiguous in their respective levels, and
neither appears in current prior art at a collision-causing frequency
(see §3 below).

---

## 2. How the decision was made

The user decided on **Archimation** prior to S74 synthesis. At the time the
original draft of this document was written, the synthesizer-architect
surveyed the 10 S74 research reports, found none had argued for a rename,
found no prior-art collision, and concluded "keep current naming" — which
at that moment meant keeping the working codename ("ARCHWINDOWS"). That
recommendation was produced without consulting the user's prior decision
and without checking runtime branding directly. It was wrong because it
was made from incomplete information.

The user's decision was not invented by the synthesizer and did not need
the synthesizer's endorsement; it was a product-level call by the owner.
The S74 research outcomes (below) are compatible with Archimation, and so
the rename proceeds without architectural controversy.

---

## 3. Prior-art survey (historical research context — no conflict with Archimation)

The S74-era survey checked three candidate alternative names to "Root of
Authority + working codename" against Google Scholar, arXiv, ACM DL, and
USENIX. None conflict with Archimation either; the survey is preserved
because the candidate names may still be useful as technical descriptors.

### 3a. "Cybernetic Authority Kernel" (CAK)

**Precision.** HIGH. The architecture IS a cybernetic system (Beer VSM
structure, algedonic channel, observer loop, autonomy controller) AND
an authority kernel (trust.ko mediates all authorization).

**Prior art scan.** No exact match for "Cybernetic Authority Kernel." Close
misses: "Cybernetic Security" (generic term), "Authority kernel" (informal
NT docs reference), Stafford Beer's "Cybersyn" (different semantic space).

**Use today.** Reserve as a technical subtitle when precision is required:
"Archimation — a Cybernetic Authority Kernel for Windows-on-Linux
runtime."

### 3b. "Dynamic Capability Kernel" (DCK)

**Precision.** HIGH. Contrasts with seL4's static capabilities. Our
capabilities decay (TRC), entangle (APE), and inherit with bound (T4).

**Prior art scan.** "Dynamic capability" is a term of art in management
studies (Teece-Pisano-Shuen 1997); Google searches would be polluted. Zero
OS-literature collision.

**Use today.** Avoid as a public descriptor due to management-literature
search pollution.

### 3c. "Adaptive Authority Substrate" (AAS)

**Precision.** MEDIUM. "Adaptive" conveys the dynamic aspect without the
management-studies pollution. "Authority substrate" is neutral.

**Prior art scan.** Clean.

**Use today.** Third-best as a descriptor. "Adaptive" is overused in
cybersecurity branding, loses distinctiveness.

---

## 4. Partial-rename drift caught 2026-04-21

The rename from the working codename to **Archimation** had been started
but not completed. Runtime branding had migrated in WBEM, fastfetch, and
systemd-boot entries, but docs, source comments, scripts, and memory files
still referenced the old codename. A 6-agent rename sweep on 2026-04-21
(S74 agents CC/DD/EE/FF + coordinator) closed the drift across:

- Source: `trust/`, `pe-loader/`, `services/`, `ai-control/`, `coherence/`
  (Agent CC)
- Docs: `docs/*.md`, `docs/research/*.md`, `CLAUDE.md`, `README.md`
  (Agent DD — this agent)
- Scripts and profile: `scripts/`, `profile/`, `packages/`, `.github/`
  (Agent EE)
- Memory: `~/.claude/memory/` (Agent FF)

Case mapping applied uniformly:
- `ARCHWINDOWS` → `ARCHIMATION`
- `Archwindows` / `ArchWindows` → `Archimation`
- `archwindows` → `archimation`
- "Arch Windows" / "Arch-Windows" → "Archimation"

Microsoft "Windows" references (Win32, kernel32, NT, Registry hives, Win32
APIs) were preserved. Only the product brand was renamed.

---

## 5. Methodology lesson

**Check runtime branding directly before writing architecture-name-
decision docs; don't infer from docs-only grep.** The original
synthesizer-architect pass missed the user's prior decision because it
surveyed research reports and prior art without checking what the product's
motd, fastfetch, systemd-boot entries, or WBEM namespace actually said
about the product name. The product had already told us its name.
Documentation is a lagging indicator; runtime branding and user intent are
leading indicators.

For future name decisions: (a) ask the user first, (b) read runtime
branding (motd, fastfetch config, boot-loader entries, WBEM namespace,
installer prompts), (c) only then survey prior art, (d) only then write
decision docs.

---

## 6. Current name-consistency

- Product name: **Archimation** (all levels — ISO, bootc image, fastfetch,
  motd, installer, docs).
- Primitive: **Root of Authority (RoA)** — unchanged; the paper-level
  name survives and is cited in `trust/include/trust_theorems.h:5-6`.
- Tagline (when useful): "Archimation — a Cybernetic Authority Kernel
  for Windows-on-Linux runtime."
- Paper reference: Zenodo DOI 10.5281/zenodo.18710335 — user-owned, uses
  "Root of Authority" and does not need to reference the product name.

---

**End of name-decision document.**
