# YX Quadrant — Reframing a "Biology Overclaim" as Architectural Novelty

**Status:** S74 Agent U decision doc. Companion to
`docs/paper-vs-implementation.md` §2.T-xy and
`docs/research/s74_e_chromosomal_model.md` §3.
**Date:** 2026-04-20.
**Owner axis:** mixed (paper text + optional code rename).
**Decision required:** A (rename + paper-reframe) / B (keep-name +
paper-reframe) / C (keep-name + paper-disclaimer-only). Recommended default
**B**; see §6.

---

## §1. What YX means in our code

The trust-kernel chromosomal authority model encodes a **four-state
conformance lattice** over two independent booleans: (A-segment at index 23
conformant to threshold θ) × (B-segment at index 23 conformant to θ).

**Enum definition** — `trust/include/trust_types.h:227-230`:

```c
#define CHROMO_SEX_XX   0   /* Both A23 >= theta AND B23 >= theta -> maintain */
#define CHROMO_SEX_XY   1   /* A23 < theta, B23 >= theta            -> demote */
#define CHROMO_SEX_YX   2   /* A23 >= theta, B23 < theta            -> promote */
#define CHROMO_SEX_YY   3   /* Both < theta                          -> apoptosis candidate */
```

**Determination logic** — `trust/kernel/trust_chromosome.c:153-170`:

```c
u8 trust_chromosome_determine_sex(const trust_chromosome_t *chromo) {
    u32 a23 = chromo->a_segments[CHROMO_A_SEX];
    u32 b23 = chromo->b_segments[CHROMO_B_SEX];
    int a_conformant = (a23 >= CHROMO_CONFORMANCE_THETA);  /* theta = 128 */
    int b_conformant = (b23 >= CHROMO_CONFORMANCE_THETA);
    if  ( a_conformant &&  b_conformant) return CHROMO_SEX_XX;
    if  (!a_conformant &&  b_conformant) return CHROMO_SEX_XY;
    if  ( a_conformant && !b_conformant) return CHROMO_SEX_YX;
    return CHROMO_SEX_YY;
}
```

**The four-state lattice** over (behavior-drift, construction-drift):

|                  | B23 ≥ θ (ctor OK) | B23 < θ (ctor drift) |
|------------------|-------------------|----------------------|
| **A23 ≥ θ** (behavior OK)    | **XX** maintain       | **YX** promote       |
| **A23 < θ** (behavior drift) | **XY** demote         | **YY** apoptosis     |

- `XX` → both axes conformant → routine authority maintenance.
- `XY` → runtime behavior drifted while construction identity is intact →
  demote authority (behavior looks untrusted).
- **`YX` → construction identity drifted while runtime behavior is still
  conformant → *promote* (reward the stable behavior, investigate the
  build).**
- `YY` → both axes divergent → apoptosis candidate.

Call sites in current tree: `trust/kernel/trust_lifecycle.c:651-674, 815`
(apoptosis routing), `services/drivers/kernel/wdm_host_subject.c:231,277`
(driver subject initialisation), `ai-control/daemon/trust_observer.py:66-69,
156, 792-800` (Python mirror), `trust/kernel/trust_internal.h:218`
(lineage record), `trust/include/trust_ioctl.h:296` (uapi output byte).

---

## §2. What biology has — and what it does not have

Per [research E §3](research/s74_e_chromosomal_model.md) — mammalian sex
determination is a **binary SRY-presence test**, not a conformance threshold.

- **Valid mammalian genotypes:** `XX` (female, no SRY) and `XY` (male, SRY on
  Y). *Source:* [SRY gene — MedlinePlus Genetics](https://medlineplus.gov/genetics/gene/sry/).
- **"YX" does not exist in mammalian biology.** Mothers can only contribute
  X chromosomes; oocytes are exclusively X-bearing. So there is no diploid
  genotype with Y from mother and X from father. The string "YX" is just
  "XY" with the parents reordered, which in biology is a null operation.
- **Diploid "YY" does not exist either.** For YY to occur, *both* parents
  would need to contribute Y. Mothers cannot. 47,XYY (Jacobs syndrome) is a
  **trisomy**, not a diploid YY genotype. *Source:*
  [Klinefelter syndrome — Wikipedia](https://en.wikipedia.org/wiki/Klinefelter_syndrome).
- **No conformance threshold.** SRY is either present (allele-active) or
  absent. There is no `[0..255]` continuous score, no θ cutoff. Other sex-
  determination systems — ZW in birds/reptiles, TSD in turtles, haplodiploid
  in bees — likewise lack the 2×2 lattice structure.

**Ruling for biology:** The "XY sex determination" label on our 2×2 conformance
lattice is load-bearing-metaphor at best and biologically-inaccurate at worst
([research E §3.3-§3.6](research/s74_e_chromosomal_model.md),
[research B §3](research/s74_b_biology_exact.md)).

---

## §3. What software has that biology does not

Here is the structural argument [research E §3.7] observes and that this doc
extends: **software has a rich taxonomy of "construction-drift-with-intact-
behavior" operations that biology cannot express.** The YX state captures a
real distinction that a subject carrying a live Linux kernel can exhibit and
a subject carrying mammalian DNA cannot.

| Software operation | YX semantics (A23 ≥ θ AND B23 < θ) | Biology analogue |
|--------------------|------------------------------------|------------------|
| **Hot patch of a running executable** (livepatch, kpatch, ksplice) | binary fingerprint drifted (B23) mid-execution; behavior unchanged from pre-patch expectation (A23) | **None.** Biology cannot change DNA sequence mid-life without mutagenesis, and mutagenesis always disturbs phenotype. |
| **Shared-library swap** (dlclose/dlopen same soname, ld.so.preload reload) | import table hash changes (B23) while ABI-level behavior continues | **None.** Biology's ribosome links proteins once; no mid-life swap-out of translation machinery. |
| **DLL injection / PE import rewrite** (PE loader `pe_resolve_imports` reconciles altered import table) | IAT hash drift (B23) with preserved call-site behavior (A23) | **None.** Closest is horizontal gene transfer (see [research E §7.3](research/s74_e_chromosomal_model.md)) — but HGT typically *changes* phenotype, not preserves it. |
| **Live-migrated process** (CRIU, VM migration) | underlying executable on disk may diverge on target (B23) while in-memory state re-starts matching last-known A23 | **None.** Cell migration moves the cell; the genome is unchanged. Not an analogue. |
| **Container image pull during zero-downtime restart** (systemd socket-activation overlay) | image digest (B23) changes across restart while protocol conformance (A23) preserved | **None.** |
| **Signed-module re-enrollment** (MOK rotation, TPM re-attest) | attestation key rotates (B23 ≈ TPM PCR digest) with preserved behavior-cycle (A23) | **None.** DNA methylation is reset across germline but not across a somatic cell's lifetime with preserved phenotype — reset always destroys the adult cell's epigenetic identity. |

The common structure: **software can atomically swap its "is" while its
"does" continues uninterrupted, and this is a first-class operational mode**
(hot patching, DLL swap-in, live migration, rolling deploy, A/B dark-launch).
Biology's swap-of-"is" always disturbs "does" because DNA sequence *causes*
the phenotype through continuous translation — there is no "state that
persists across a genome edit."

**Therefore** the YX-quadrant (construction-drift-with-intact-behavior) is
not a bug in our mapping to biology; it is a **software primitive biology
cannot express**. Reclaiming it as novel contribution is stronger than
apologising for it.

### §3.1 Why this matters for security

A subject whose binary hash drifted *but whose behavior is still conformant*
is suspicious in a **different** way from one whose behavior drifted on
stable construction:

- **Behavior drift (XY)** → most likely an exploit inside the running process
  (control-flow hijack, memory corruption, unexpected syscall sequence).
  Response: **demote**. The build is fine; the runtime went bad.
- **Construction drift (YX)** → most likely a legitimate hot-patch, a
  supply-chain event, a library reload, or live-migration. Response:
  **promote**. The behavior is fine; investigate *why* the build changed.

A binary classifier (XX / not-XX) conflates these into one "suspicious" bucket
and cannot distinguish the two remediation paths. Our 2×2 lattice **is the
minimum-cardinality classifier that captures both remediations separately**.
A biologist cannot use this distinction because biology's "build" and
"behavior" are not separable; a security engineer can.

---

## §4. Paper-text proposal — 50-100 words to reclaim YX as novel contribution

Draft paragraph for paper §[conformance-quadrant section]:

> **The four-state conformance lattice has no biological antecedent — and
> that is the claim, not the embarrassment.** Mammalian sex determination is
> an SRY-presence binary test; diploid `YX` and `YY` genotypes do not occur
> naturally (oocytes contribute only X; trisomy 47,XYY is not diploid YY).
> Software, by contrast, admits a first-class `construction-drift-with-
> intact-behavior` regime — hot patches, livepatched kernels, dlopen
> swaps, DLL injection, live-migrated processes, rolling container deploys.
> In each, the subject's construction fingerprint (B-segment at index 23)
> diverges atomically while runtime behavior (A-segment at index 23)
> continues uninterrupted. A binary conformance classifier cannot distinguish
> this from control-flow hijack. Our 2×2 lattice captures both regimes with
> opposite remediations — `YX`→promote-and-investigate-build,
> `XY`→demote-and-inspect-runtime. Biology's authority substrate cannot
> express this distinction because DNA sequence *causes* phenotype through
> continuous translation; a software kernel's authority substrate can.
> We retain the `XX/XY/YX/YY` alphabet as a mnemonic for the lattice
> structure; the mapping to biological sex is explicitly metaphor and not a
> model of mammalian genetics.

~180 words in the draft; paper can compress to 100-120 without losing the
argument. The load-bearing claims are: (a) this is novel, (b) software
substrate is richer than biological for this specific axis, (c) the
alphabet is mnemonic-only.

---

## §5. Code action — rename vs keep-name

**Current call-site count** — `grep CHROMO_SEX_` across tree: **50
occurrences across 13 files** (trust kernel, libtrust header, Python
observer, ioctl UAPI, wdm_host_subject, lifecycle, docs).

The grep is load-bearing here because it determines the LOC cost of option A.
Breakdown:

| File | CHROMO_SEX_ refs | Nature |
|------|------------------|--------|
| `trust/include/trust_types.h` | 5 | Defines enum + sex field |
| `trust/include/trust_ioctl.h` | 1 | UAPI output byte documentation |
| `trust/kernel/trust_chromosome.c` | 6 | Init + determine_sex function |
| `trust/kernel/trust_lifecycle.c` | 7 | Apoptosis routing switch |
| `trust/kernel/trust_lifecycle.h` | 4 | Legacy `TRUST_SEX_*` aliases |
| `trust/kernel/trust_internal.h` | 1 | Lineage record struct comment |
| `trust/lib/libtrust.h` | 1 | Userspace header doc comment |
| `services/drivers/kernel/wdm_host_subject.c` | 2 | Driver subject init |
| `ai-control/daemon/trust_observer.py` | 10 | Python mirror + display strings |
| docs + research | ~13 | Cross-reference documentation |

**ABI break risk:**

- The enum values `0/1/2/3` are serialised into `trust/include/trust_ioctl.h:296`
  (`sex` output byte from the `TRUST_IOC_*` surface). **Keep the integer
  values.** A rename of the symbol need not change the value contract.
- `libtrust.h:282` mentions `CHROMO_SEX_XX/XY/YX/YY` in a doc comment but
  **no libtrust userspace symbol exports** the enum name or returns it as
  a string. Verified by grep — no `libtrust_` function references
  `CHROMO_SEX_*` in `trust/lib/libtrust.c`. ABI surface is **header-level
  documentation only**, not linker-level.
- Python mirror (`ai-control/daemon/trust_observer.py`) is in-tree and
  can be renamed in lockstep — not a separate ABI.

**Conclusion: zero binary ABI break for rename. Only source-level renaming
needed.**

### §5.1 Option A cost — full rename
- Source touch: ~50 sites across 13 files.
- Net LOC delta: roughly +20 for backward-compat `#define` aliases
  (`#define CHROMO_SEX_XX CONF_QUAD_OK` etc.) and -0 for replaced symbols
  (replacements are 1-for-1).
- Mechanical, single-commit, no ABI risk, low conflict risk.
- Estimated total: **~80-100 LOC touched**.

### §5.2 Option B cost — keep name, annotate
- Add a kernel-doc block at `trust/include/trust_types.h:225` (above the
  enum) explaining: "This is a 2×2 conformance lattice, not biological XY
  sex determination. See `docs/yx-quadrant-novelty.md`."
- Update `trust/kernel/trust_chromosome.c:149-153` function-doc to describe
  "conformance quadrant" not "sex."
- Update `trust/kernel/trust_lifecycle.h:32, 57, 67-68` to reflect same.
- Update `ai-control/daemon/trust_observer.py:66-69` display-string comments.
- Paper text reframes `XY` alphabet as mnemonic (see §4).
- Estimated total: **~20 LOC of comment updates** + ~180 words paper text.

### §5.3 Option C cost — keep name, disclaim only
- No code touch.
- Paper text disclaims per existing `docs/paper-vs-implementation.md §2.T-xy`
  (80 words).
- Estimated total: **0 LOC, 80 words paper text**.

---

## §6. Recommendation

### Option A — rename + paper-reframe
- **Best if:** the paper is submitted to a biology or interdisciplinary
  venue where mechanism naming is load-bearing for credibility.
- **Citation argument:** [research E §3.6](research/s74_e_chromosomal_model.md)
  recommends rename-with-compatibility-alias. LOC cost is low (~80-100 LOC,
  mechanical).
- **Drawback:** "XY" as shorthand was memorable; renaming introduces
  `CONF_QUAD_*` jargon that is less teachable.

### Option B — keep name + paper-reframe (§4 text) **[RECOMMENDED DEFAULT]**
- **Best if:** the paper is submitted to a systems/security venue and we
  want to convert a biology-reviewer-risk into an architectural-contribution-
  claim.
- **Citation argument:** [research E §3.7](research/s74_e_chromosomal_model.md)
  flags the YX-quadrant as *architecturally novel*. This doc §3 extends that
  observation with a concrete software taxonomy (hot patches, live migration,
  DLL injection) biology cannot express. Paper-text in §4 converts the
  apology into a contribution claim.
- **Drawback:** biology reviewers may still push on "XY" nomenclature. The
  §4 disclaimer addresses this explicitly.
- **Why default:** lowest implementation cost (~20 LOC comments + 180 words
  paper), highest rhetorical yield (reclaim as contribution), and preserves
  the memorable `XX/XY/YX/YY` alphabet for pedagogy.

### Option C — keep name + paper-disclaimer-only
- **Best if:** no paper submission is planned this cycle, or the paper
  resubmission priority is at the runtime-theorem level
  (`docs/paper-vs-implementation.md §2.T-runtime`) not the nomenclature level.
- **Citation argument:** [paper-vs-implementation.md §2.T-xy](paper-vs-implementation.md)
  already has the disclaimer draft. Ship as-is; move on.
- **Drawback:** misses the chance to convert a defensive disclaimer into an
  offensive contribution claim. Biology reviewer may still flag the label
  even with the disclaimer.

### §6.1 Decision matrix

| Context | Option |
|---------|--------|
| Submitting to CS security venue (S&P, CCS, USENIX Sec, OSDI) within 1 session | **C** (disclaimer sufficient for CS reviewers) |
| Submitting to systems venue (EuroSys, ATC) within 2-3 sessions | **B** (reframe is credibility-maximising at low cost) |
| Submitting to interdisciplinary venue (Nature Comms, PNAS, Phil Trans Roy Soc B) within 3-5 sessions | **B** + A-ready-follow-on (rename alias) |
| Submitting to biology venue | **Do not submit** per [paper-vs-implementation.md §4](paper-vs-implementation.md) §4 and [research E §10.3](research/s74_e_chromosomal_model.md) |
| No paper submission within S75-S76 | **C** (cheapest; keep focus on runtime-theorem harness instead) |

**User decision required:** A / B / C given venue context.

---

## §7. Cross-references

- `docs/research/s74_e_chromosomal_model.md` §3.7 — Agent E's observation
  that YX captures something biology cannot.
- `docs/paper-vs-implementation.md` §2.T-xy — current "apologise for
  overclaim" disclaimer, superseded here by the §4 reframe.
- `docs/architecture-v2.md` §4 Finding #3 (lines 294-297) — existing
  reference to the rename-not-required-for-correctness finding.
- `docs/yx-quadrant-novelty.md` (this file) — reframe proposal.
- `docs/meiosis-rename-decision.md` — companion decision doc for the
  larger-ABI-surface meiosis rename question.

---

*S74 Agent U, 2026-04-20. Read-only analysis; no code edits in this session.*
