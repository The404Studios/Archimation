# Meiosis Rename Decision — Mechanism Gap A/B/C

**Status:** S74 Agent U decision doc. Companion to
`docs/paper-vs-implementation.md` §2.T-meiosis,
`docs/research/s74_b_biology_exact.md` §3, and
`docs/research/s74_e_chromosomal_model.md` §4.
**Date:** 2026-04-20.
**Owner axis:** mixed (code rename + paper text).
**Decision required:** A (full rename) / B (disclaimer-only) / C (hybrid
public-rename + internal-preserve). Default **B** for CS venues, see §5.

---

## §1. Finding summary — what `trust_meiosis()` actually does vs what
meiosis mechanistically is

### What the code does

`trust/kernel/trust_meiosis.c:237-448` — `trust_meiosis(A, B, out_shared)`:

1. Two parent subjects `A` and `B` (both diploid-analog, full 23-pair
   chromosomes).
2. Fresh 32-byte `random_blind` per meiosis call
   (`trust_meiosis.c:281-282`: `get_random_bytes(blind, sizeof(blind))`).
3. For each pair `i` in `[0..22]` (`trust_meiosis.c:307-327`):
   - Pick **dominant parent** (higher `trust_score`; tie-break by
     `subject_id`).
   - Take dominant's `a_segments[i]` and `b_segments[i]`.
   - Hash each with SHA-256 (segment ‖ random_blind) → 32-byte digest.
   - First 4 bytes of digest → new segment.
4. `S_shared = min(S_A, S_B)`; token cap `= (C_A + C_B) / 4`.
5. Fresh 32-byte APE seed (not inherited from either parent).
6. Single output shared subject tagged `TRUST_FLAG_SHARED_R2` (ring −2
   sentinel).
7. Bonded to both parents (`trust_meiosis.c:394-407`); apoptosis of either
   parent cascades to the shared subject.

This is a **cryptographic key-derivation ceremony** — blinded per-pair
SHA-256 under fresh per-call randomness, dominant-parent selection,
bounded combined authority, cascaded lifetime. Closest real analogue:
Diffie-Hellman-style dual-party derivation + threshold secret-sharing
bounded-output.

### What biological meiosis actually is

Per [research B §3](research/s74_b_biology_exact.md) and
[research E §4](research/s74_e_chromosomal_model.md), real meiosis has
**five essential properties**:

| # | Property | In `trust_meiosis()`? |
|---|----------|----------------------|
| 1 | **Homolog pairing** via synaptonemal complex (Zip1, Msh4/5, Mer3, Mlh1/3) | NO — no pairing step |
| 2 | **DSB-mediated crossover** via Spo11 + Holliday junctions | NO — no DSBs, no HJ, no resolution ambiguity |
| 3 | **Independent assortment** at Metaphase I (2²³ ≈ 8.4M combinations) | NO — each pair comes from a single dominant parent |
| 4 | **Reductional division** 2n → n | NO — output is still "diploid-like" (23 pairs) |
| 5 | **Four haploid products** | NO — one shared subject produced |

**Fidelity: 0/5 faithful properties.** [Research E §4.3](research/s74_e_chromosomal_model.md)
and [research B §3 "9 of 9 essential meiotic properties fail"](research/s74_b_biology_exact.md)
are consistent on this point.

Primary biology citations:
- Zickler D, Kleckner N. "Recombination, Pairing, and Synapsis of Homologs
  during Meiosis." *Cold Spring Harb Perspect Biol* 7(6), 2015.
- Hunter N. "Meiotic Recombination: The Essence of Heredity." *CSH Perspect
  Biol* 7(12), 2015.
- Voelkel-Meiman K et al. "Synaptonemal complex protects double-Holliday
  junctions during meiosis." *bioRxiv* 2024.09.14.613089v2.
- Lee MS et al. "Holliday junction-ZMM protein feedback enables meiotic
  crossover assurance." *Nature* 2025.

### The naming gap

The code comments themselves acknowledge the ambiguity —
`trust_meiosis.c:1-9` explicitly says the function is *"entirely distinct
from the legacy trust_lifecycle_meiotic_combine"*. This is a tell: "meiosis"
already means two different things in the repo. [Research E §4.5](research/s74_e_chromosomal_model.md)
flags this as "the single most over-claimed biology vocabulary in the
codebase."

---

## §2. Option A — full rename to `trust_dual_authority_bond()`

### §2.1 Call-site inventory

Per grep at HEAD:

| Scope | Occurrences | Files |
|-------|-------------|-------|
| Kernel source (internal) | 63 | `trust/kernel/trust_meiosis.c` (40), `trust/kernel/trust_meiosis.h` (22), `trust/kernel/trust_invariants.c` (1) |
| Kernel build | 1 | `trust/kernel/Kbuild:7` — `trust_meiosis.o` |
| Package build | 2 | `packages/trust-dkms/PKGBUILD` (source manifest guard) |
| Tests | 1 | `tests/integration/test_roa_conformance.py:414` — `trust_meiosis_request` |
| Docs | ~20 | `docs/roa-conformance.md`, `docs/architecture-v2.md`, `docs/s75_roadmap.md`, `docs/paper-vs-implementation.md`, `docs/architecture-meta-exploit-s73.md`, `docs/architecture-invariants.md`, `docs/research/s7{1,3,4}_*.md` |
| User memory | (cross-reference — Agent M territory; flag only) |

**Total surface:** ~112 source/doc occurrences across ~21 files. Kernel-
internal is the heavy lifter (63/112).

### §2.2 Userspace ABI surface — CHECKED AND CLEAR

Critical verification: **the `trust_meiosis*` symbol is NOT exported
through libtrust.** Grep results:

- `trust/lib/libtrust.c` — 0 occurrences of "meiosis" or `trust_meiosis*`.
- `trust/lib/libtrust.h` — 0 symbol declarations for meiosis.
- `trust/include/trust_ioctl.h` — 0 occurrences of `TRUST_IOC_*_MEIOSIS` or
  `meiosis` in the UAPI header.

`docs/roa-conformance.md:192, 197` claims a libtrust wrapper at
`trust/lib/libtrust.c:1292` and symbol `LIBTRUST_1.4`. **This claim is stale
(documentation drift).** The wrapper does not exist at HEAD; only
`trust_meiosis_request_by_id()` at `trust/kernel/trust_meiosis.c:454`
(EXPORT_SYMBOL_GPL'd, kernel-to-kernel) is live. This is a separate phantom-
claim of the same pattern flagged in `docs/phantom-claim-investigation-
contusion-ai.md`.

**Conclusion: zero binary ABI break on rename.** Kernel-internal symbols are
the entire surface. The EXPORT_SYMBOL_GPL names
(`trust_meiosis`, `trust_meiosis_request_by_id`) are consumed only by
other kernel modules built in the same DKMS package — rename them and
rebuild together.

### §2.3 Rename plan for Option A

1. **Files renamed:**
   - `trust/kernel/trust_meiosis.c` → `trust/kernel/trust_dual_auth_bond.c`
   - `trust/kernel/trust_meiosis.h` → `trust/kernel/trust_dual_auth_bond.h`
2. **Symbols renamed:**
   - `trust_meiosis(A, B, out)` → `trust_dual_authority_bond(A, B, out)`
   - `trust_meiosis_request_by_id()` → `trust_dual_auth_bond_by_id()`
3. **Macros renamed:**
   - `TRUST_MEIOSIS_ID_BASE/LIMIT/TRIES/EVACT_CAP` → `TRUST_DAB_*`
4. **Kbuild entry updated:** `trust/kernel/Kbuild:7`.
5. **PKGBUILD source manifest updated:** `packages/trust-dkms/PKGBUILD` (S68
   manifest guard; requires coordinated update in
   `scripts/build-packages.sh::verify_trust_dkms_manifest()` — per Session
   67 Agent A5).
6. **Sysfs path migration:** `trust_meiosis.c:670, 674` create
   `/sys/kernel/trust_meiosis` kobject. Option A renames this to
   `/sys/kernel/trust_dual_auth_bond`. **This IS a userspace-visible break**
   — but only for direct sysfs readers (test scripts, observability
   dashboards). Mitigation: keep a legacy sysfs symlink
   `trust_meiosis` → `trust_dual_auth_bond` for one release.
7. **Test file updated:** `tests/integration/test_roa_conformance.py:414`.
8. **Doc updates:** cross-references in ~20 markdown files; mostly
   `rg -l "trust_meiosis\b" | xargs sed` would do it but doc-by-doc review
   is warranted given the biology-metaphor argument is itself load-bearing in
   some of those docs (e.g., architecture-v2.md).

### §2.4 LOC estimate for Option A

- Kernel source: ~100 LOC of renames (mechanical, 1-for-1).
- Kbuild + PKGBUILD + S68 manifest guard: ~10 LOC.
- Sysfs compatibility symlink: ~20 LOC (new `trust_meiosis_compat_init()`).
- Tests: ~10 LOC.
- Docs: ~60 LOC of rewrites across 20 files.
- **Total: ~200 LOC across ~25 files.**

Estimated agent-cost: **1-2 sessions** with a verification QEMU smoke after.
Matches [research E §11.2](research/s74_e_chromosomal_model.md) recommendation
and [paper-vs-implementation.md §5 row 1](paper-vs-implementation.md)
estimate of 200 LOC.

### §2.5 Pros and cons — Option A

**Pros:**
- Mechanistically honest.
- Biology-peer-review safe ([research E §10.2](research/s74_e_chromosomal_model.md)
  — interdisciplinary venues would flag the name).
- Resolves the in-tree ambiguity between `trust_meiosis()` and
  `trust_lifecycle_meiotic_combine` ([research E §4.5](research/s74_e_chromosomal_model.md)).
- Kernel symbol names match semantic intent (key-derivation, bounded
  authority).

**Cons:**
- Sysfs break for direct readers (mitigated by symlink).
- Doc churn (~20 markdown files, many with surrounding biology-metaphor
  narrative that needs re-anchoring).
- "Meiosis" was a memorable teach-moment for architectural newcomers; new
  name is less evocative.
- Non-trivial session cost (~200 LOC, 1-2 sessions) at a time when other
  S75 work is higher-priority
  (`docs/paper-vs-implementation.md §5` shows 5 mixed items).

---

## §3. Option B — disclaimer-only (keep name, add paper text + code comment)

### §3.1 Paper footnote draft (80-120 words)

> **On the name "meiosis."** The term *meiosis* is used analogically for the
> dual-parent key-derivation ceremony described in §[function-spec]; the
> mechanism does not match biological meiosis (see Zickler & Kleckner,
> *CSH Perspect Biol* 2015). The primitive lacks homolog pairing via
> synaptonemal complex, Spo11-mediated double-strand-break crossover,
> independent assortment, reductional division, and four-haploid-product
> generation. It is cryptographically characterised as blinded per-pair
> SHA-256 derivation under fresh per-call randomness, with dominant-parent
> selection and bounded combined authority (`min(S_A, S_B)`). We retain the
> name for its mnemonic value — the dual-parent redundancy and the
> cascaded-apoptosis-on-either-parent-death resembles meiosis in *intent* —
> and because an alternative name (*dual authority bond* / *joint seal*)
> has no established scientific currency.

~115 words in the draft; paper can compress to 90 without losing the
structure.

### §3.2 Kernel-source comment addition

Current header at `trust/kernel/trust_meiosis.c:1-41` acknowledges partial
ambiguity ("entirely distinct from the legacy `trust_lifecycle_meiotic_combine`").
Option B extends this with:

```c
/*
 * NOMENCLATURE NOTE — BIOLOGY GAP
 *
 * The name "meiosis" here is analogical for a DUAL-PARENT KEY-DERIVATION
 * CEREMONY — not biological meiosis. None of the five essential meiotic
 * properties hold in this function:
 *
 *   - no synaptonemal-complex homolog pairing
 *   - no Spo11-mediated double-strand-break crossover
 *   - no independent assortment at Metaphase I (per-pair dominance only)
 *   - no reductional division (output is still "diploid-like")
 *   - no four-haploid-products generation (one shared subject produced)
 *
 * What this function IS: blinded per-pair SHA-256 derivation under fresh
 * per-call randomness, dominant-parent selection, bounded combined
 * authority (min(S_A, S_B)), cascaded apoptosis.
 *
 * The name is retained for its mnemonic value (dual-parent redundancy)
 * and because no alternative has established scientific currency.
 *
 * See docs/paper-vs-implementation.md §2.T-meiosis,
 *     docs/research/s74_b_biology_exact.md §3,
 *     docs/research/s74_e_chromosomal_model.md §4.
 */
```

### §3.3 LOC estimate for Option B

- Paper text: ~115 words (author controls).
- Kernel source header: ~25 LOC of comments at `trust_meiosis.c:1-9`
  expansion.
- Cross-links in `trust_meiosis.h:1-40` (file-header already has some
  nomenclature note; expand by ~10 LOC).
- **Total: ~35-50 LOC of comments + paper footnote.**

Estimated agent-cost: **well under one session.**

### §3.4 Pros and cons — Option B

**Pros:**
- Zero ABI risk.
- Zero sysfs break.
- Preserves the existing tree state — no DKMS repack, no QEMU smoke
  regression risk.
- Fast — single commit.
- Biology-metaphor pedagogy retained in architecture-v2, roa-conformance,
  and paper prose.
- Matches the strategy already adopted for `/docs/paper-vs-implementation.md
  §2.T-xy` (disclaimer over rename) — policy consistency.

**Cons:**
- Audience-dependent credibility cost:
  - **CS security reviewers** (S&P, CCS, USENIX Sec, OSDI): tolerant,
    disclaimer sufficient.
  - **Interdisciplinary reviewers** (Nature Comms, PNAS, Phil Trans Roy
    Soc B): may still push on the name even with disclaimer.
  - **Biology reviewers** (Nature, Cell): would reject regardless —
    [research E §10.3](research/s74_e_chromosomal_model.md) and
    [paper-vs-implementation.md §4](paper-vs-implementation.md) both say
    *do not submit to biology venues*.

---

## §4. Option C — hybrid public-rename + internal-preserve

### §4.1 Mechanism

Rename only the **public-facing userspace API** (EXPORT_SYMBOL_GPL + any
libtrust wrapper we build later) to `trust_dual_authority_bond()`, keep
internal static helpers and file names as "meiosis":

- `trust/kernel/trust_meiosis.c` — **file name unchanged**, internal helpers
  unchanged.
- `trust_meiosis()` — **add** `trust_dual_authority_bond()` as an inline
  alias. Both EXPORT_SYMBOL_GPL; one symbol becomes the documented public
  name, the other kept for source compatibility.
- `trust_meiosis_request_by_id()` — same pattern.
- Sysfs: both `/sys/kernel/trust_meiosis/*` and
  `/sys/kernel/trust_dual_auth_bond/*` with identical attribute files
  (two-symlink pattern).
- Paper text uses `dual_authority_bond`; kernel-source comments and docs
  continue to use "meiosis."

### §4.2 LOC estimate for Option C

- Alias symbol defs: ~20 LOC (inline wrapper + `EXPORT_SYMBOL_GPL` twice).
- Sysfs symlink: ~30 LOC.
- Paper text: ~50 words (shorter than Option B footnote because the code is
  mostly self-documenting via the new public name).
- Tests: 0 (tests can stay on `trust_meiosis_request` or migrate optionally).
- Docs: ~20 LOC total update to point to the public name.
- **Total: ~80 LOC + 50 words paper.**

### §4.3 Pros and cons — Option C

**Pros:**
- ABI-safe transition (old symbol kept as alias).
- Userspace sees the mechanistically honest name.
- Kernel source keeps pedagogical `meiosis` heuristic.

**Cons:**
- **Schizophrenic naming** — kernel says "meiosis," userspace sees
  "dual_authority_bond." Future maintainers read inconsistent vocabulary.
- Sysfs two-symlink pattern doubles the observability surface (and the
  edge cases — what if a writer writes both?).
- Paper still has to explain why the code says `trust_meiosis` when the
  public API says `trust_dual_authority_bond`. That explanation is roughly
  the same length as Option B's footnote — so the paper-cost advantage of
  C over B is small.

---

## §5. Recommendation matrix

| Paper submission context | Recommended option |
|--------------------------|---------------------|
| **CS security venue** (S&P, OSDI, CCS, USENIX Sec, NDSS) | **B** — disclaimer sufficient; CS reviewers treat biology as pedagogy |
| **Systems venue** (EuroSys, ATC) | **B** — same reasoning; runtime-theorem validation is a larger blocker than naming |
| **Interdisciplinary** (Nature Comms, PNAS, Phil Trans Roy Soc B) | **B** with a prominent disclaimer in Methods; consider pre-registering Option A as a follow-on |
| **Biology venue** (Nature, Cell, J Cell Biol) | **Option A required**, but — per [paper-vs-implementation.md §4](paper-vs-implementation.md) — **do not submit to biology venues**. This paper is not biology |
| **No paper submission planned in S75-S76** | **B** — cheapest, preserves state, keeps focus on runtime-theorem harness (`docs/runtime-theorem-validation.md`) and bisim (research I) which are higher-priority code items |

### §5.1 Why B is the default

- **Lowest implementation cost** (~50 LOC, < 1 session).
- **Consistent with the policy already adopted** for `CHROMO_SEX_*`
  (`docs/yx-quadrant-novelty.md` §6 also recommends B as default).
- **Does not block higher-priority S75 items** — per
  [paper-vs-implementation.md §5](paper-vs-implementation.md), the three
  highest-priority S75 mixed items are:
  1. T-runtime adversarial harness (~800 LOC)
  2. Substrate-delta empirical bisim (~680 LOC)
  3. T-veto typestate enforcement (~80 LOC)
  None of these are advanced by renaming meiosis. An Option A session budget
  is better spent on the harness.
- **Paper-revision readiness** — 115-word footnote is author-controlled
  text, no code coordination needed for a Zenodo revision upload.

### §5.2 Conditions that flip the default to A

- User decides to pursue an interdisciplinary venue AND biology reviewers
  are likely (Nature Comms with biology reviewer; Phil Trans Roy Soc B).
- User values biology-vocabulary audit pass over paper-velocity.
- User has ≥2 S75 sessions to allocate.

### §5.3 Conditions that flip the default to C

- The user builds a libtrust userspace wrapper in S75+ (the phantom claim
  at `docs/roa-conformance.md:192, 197` becomes real). Then Option C lets
  the new userspace API launch with the honest name while keeping kernel
  source unchanged.

---

## §6. User decision required

**Question:** A / B / C given:
- target venue for the next paper submission?
- session budget available in S75-S76?
- whether biology reviewers are in scope?

**Default if no venue context is given:** **B** (disclaimer + kernel
header comment, ~50 LOC, ~115 words paper).

---

## §7. Cross-references

- `docs/paper-vs-implementation.md` §2.T-meiosis — current disclaimer
  draft this doc supersedes/extends.
- `docs/research/s74_b_biology_exact.md` §3 — 9-property side-by-side
  comparison.
- `docs/research/s74_e_chromosomal_model.md` §4 — rename recommendation.
- `docs/yx-quadrant-novelty.md` — companion decision for the XY enum rename
  (smaller surface, same A/B pattern).
- `docs/phantom-claim-investigation-contusion-ai.md` — discovered during §2.2
  research that `docs/roa-conformance.md:192, 197` claims a non-existent
  libtrust wrapper; same pattern as the S51 phantom contusion/ai endpoint.

---

*S74 Agent U, 2026-04-20. Read-only analysis; no code edits in this session.*
