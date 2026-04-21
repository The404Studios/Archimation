# S74-C — Endosymbiosis & Mitochondrial Mechanism Depth for ARCHWINDOWS

**Framework agent**: C of 10 parallel (S74 research axis: mitochondrial biology →
retrograde signaling primitives).

**Date**: 2026-04-20
**Prerequisite**: S73-G (`docs/research/s73_g_endosymbiosis.md`) established the
high-level PE-loader-as-mitochondrion mapping. This document goes deeper on
**14 specific mitochondrial mechanisms**, grading each against our code with a
fidelity rating, and identifies the retrograde-signaling gaps.

---

## 0. Executive Summary

The mitochondrion doesn't just do ATP synthesis for the cell — it runs an
elaborate **inter-organelle signaling protocol** that includes stress alarms
(mtUPR/ATF5), systemic hormone-like mitokines (FGF21/GDF15), DAMP alarms
(N-formyl peptides, cardiolipin exposure, mtDNA release), controlled-death
triggers (cytochrome c release), and bidirectional calcium transfer at contact
sites (MAMs). Collectively these close the feedback loop that lets the nucleus
"hear" what the organelle is doing.

S73-G mapped PE loader → mitochondrion structurally. This S74-C audit asked:
of the 14 known mechanisms by which a real mitochondrion signals up to its
nucleus, how many does ARCHWINDOWS implement, and at what fidelity?

**Verdict in one table**:

| Mechanism | Signal produced | ARCHWINDOWS analogue | File:line | Fidelity |
|---|---|---|---|---|
| 1. SET (origin) | ontological, not runtime | PE loader loaded as foreign symbiont, marked `TRUST_DOMAIN_WIN32` | `ai-control/daemon/trust_observer.py:31` | faithful |
| 2. mtDNA retention (37 genes) | genome partitioning | CoRR-locked core stays in PE stubs | `pe-loader/dlls/kernel32/kernel32_file.c:39` | partial |
| 3. TOM/TIM protein import | cross-membrane transfer | `pe_find_crt_wrapper()` ms_abi↔sysv_abi table (~120 wrappers) | `pe-loader/loader/pe_import.c` | faithful |
| 4. MICOS cristae morphology | stress-driven topology change | **ABSENT** — no internal PE-runtime reorganization under stress | — | absent |
| 5. Drp1/Mfn fission-fusion | mitochondrial network dynamics | Trust kernel DRP1-equivalent veto on PE reproduction via `TRUST_ACTION_LOAD_KERNEL_BINARY`; no user-mode fission/fusion of PE subsystems | `trust/kernel/trust_dispatch.c` (S65 A1) | metaphor-only |
| 6. PINK1/Parkin mitophagy | damaged-mitochondrion tagging + engulfment | `trust_lifecycle_apoptosis` + cascade depth 4, but **no ubiquitin-style "tag then engulf" pathway** | `trust/kernel/trust_lifecycle.c:465` | partial |
| 7. mtUPR (ATF5) | chaperone/protease upregulation | **ABSENT** — no PE-runtime "install more stubs / switch to stricter trust gate" response to stub-fault density | — | absent |
| 8. Mitokines (FGF21/GDF15) | systemic circulating stress signal | **ABSENT** — event bus has no "PE subsystem aggregate stress" event type | `pe-loader/include/eventbus/pe_event.h` | absent |
| 9. mtROS redox signaling (NRF2) | oscillating redox → adaptive antioxidant response | `behavioral_markov.py` bigram observation is the closest analog but lacks redox-style smoothing | `ai-control/daemon/behavioral_markov.py` | metaphor-only |
| 10. Cardiolipin exposure | pre-apoptotic "I am damaged" tag on OMM | Oscillation detector sets `TRUST_FLAG_FROZEN` which flips immune status, but not a dedicated **pre-apoptotic surface marker** | `ai-control/daemon/trust_observer.py:403` | partial |
| 11. N-formyl peptides (fMet) | bacterial-signature DAMPs → FPR1 → neutrophil recruitment | **ABSENT** — no "leak from crashed PE → innate immune pattern recognition" pathway | — | absent |
| 12. Cytochrome c release | MOMP + apoptosome assembly → caspase cascade | `trust_algedonic_emit()` with reason `TRUST_ALG_CASCADE_APOPTOSIS` is the direct analog | `trust/kernel/trust_algedonic.c:65` | faithful (scaffold), **UNWIRED to cortex** |
| 13. MAMs (ER-mito contacts) | Ca²⁺ transfer IP3R→VDAC1→MCU at ~20nm | **ABSENT** — no coherenced ↔ PE subsystem tight-coupled "metabolic" channel; `coherence_bridge.py` is threshold-setpoint only | `ai-control/cortex/coherence_bridge.py` | metaphor-only |
| 14. Mitochondrial donation therapy | replace sick mito with healthy donor | **ABSENT** — no "import pre-built healthy PE runtime from trusted image" rescue path | — | absent |

**Score**: 2 faithful, 3 partial, 3 metaphor-only, 6 absent. Of the 14 specific
mitochondrial signaling mechanisms, we implement **one-quarter** of the surface
area with faithful fidelity, and the specific biological-move that is most
absent is systemic stress broadcast (mitokines/mtUPR/fMet) — precisely the
retrograde-signaling axis flagged in the task specification.

**Top 3 findings** (ordered by architectural leverage):

1. **Cytochrome c release exists but is dead-end.** `trust_algedonic.c:65` has
   a working kernel-side emit function with the correct reason codes
   (`TRUST_ALG_CASCADE_APOPTOSIS`, `TRUST_ALG_CANCER_DETECTED`, etc.), ring
   buffer, `/dev/trust_algedonic` miscdevice, and sysfs counters. **But no
   cortex reader exists.** Grep for `/dev/trust_algedonic` in
   `ai-control/cortex/*` returns zero hits. The kernel is releasing
   cytochrome-c-equivalent packets into a ring buffer no one is draining.
   Build deliverable: `ai-control/cortex/algedonic_reader.py` (~80 LOC) that
   opens the char device, blocks on `read(sizeof(struct trust_algedonic_packet))`,
   and fan-outs into `EventBus._dispatch_async()` as synthetic urgent events
   with a new `SourceLayer.ALGEDONIC = 5`. Fastest-biggest-win fix in this audit.

2. **No mitokine-class aggregate signal.** The event bus (`pe_event.h`) emits
   **per-process** events (PE_EVT_LOAD, PE_EVT_DLL_LOAD, PE_EVT_UNIMPLEMENTED_API,
   PE_EVT_EXIT). It has no **subsystem-level** "PE aggregate stress"
   signal. Biology's answer to "individual process events don't tell the liver
   the muscle is in trouble" is FGF21 and GDF15 — secreted cytokines that
   aggregate tissue-level stress into a single scalar circulating in blood
   that distant organs subscribe to. Proposal: `PE_EVT_SUBSYSTEM_STRESS`
   (source=RUNTIME, type=0x16), payload = rolling-window (stub_call_rate,
   trust_deny_rate, dll_unresolved_rate, pe_crash_rate, mean_runtime_delta),
   emitted by pe_event.c once per second from the drain thread. Cortex
   subscribes and feeds it to decision_engine. This is the single most
   important retrograde-signaling gap.

3. **PE_EVT_EXCEPTION is defined but never emitted.** The event type code
   exists in `pe-loader/include/eventbus/pe_event.h:47` but grep for
   `pe_event_emit(PE_EVT_EXCEPTION` returns zero matches. SEH handlers in the
   PE loader swallow exceptions silently before the cortex hears of them.
   This is the "PE crashed, cytochrome c leaked" signal missing from the
   biological cascade. Build deliverable: instrument
   `pe-loader/dlls/kernel32/kernel32_seh.c` and the Vectored Exception
   Handler chain to emit PE_EVT_EXCEPTION with (exception_code, fault_va,
   caller_pc, dll_name) on every unhandled SEH record. ~40 LOC. Unlocks
   exception-correlation in decision_engine.

The rest of the document: each of the 14 mechanisms, one section each,
exactly as required (biology citation, signal, ARCHWINDOWS analogue grep,
gap sketch, fidelity rating).

---

## 1. Lynn Margulis 1967 SET + Martin & Mentel 2010 update

### (a) Primary citations

Margulis (as Sagan) L. "On the origin of mitosing cells". *J. Theor. Biol.*
14(3):225-274 (1967). [1]

Martin W.F., Mentel M. "The Origin of Mitochondria". *Nature Education*
3(9):58 (2010). [2]

Archibald J.M. "Endosymbiosis and Eukaryotic Cell Evolution". *Curr. Biol.*
25(19):R911-R921 (2015). [3]

Imachi H. et al. "Isolation of an archaeon at the prokaryote-eukaryote
interface". *Nature* 577:519-525 (2020). [4]

Archibald J.M. "Lynn Margulis and the endosymbiont hypothesis: 50 years
later". *Mol. Biol. Cell* 28(10):1285-1287 (2017). [5]

### (b) Signal / event

SET itself produces no runtime signal — it describes a **phylogenetic event**
(~2 Gya) that explains why eukaryotes have two genomes, two ribosomal classes,
and a foreign-origin organelle. The signal is ontological: "this component
is from a different lineage".

### (c) ARCHWINDOWS analogue — present

The PE loader is loaded as a foreign symbiont and every PE process is
permanently tagged `TRUST_DOMAIN_WIN32 = 1` in the trust subject:

```
ai-control/daemon/trust_observer.py:31:  TRUST_DOMAIN_WIN32 = 1
```

This marker is **permanent** and **inherited** — identical to how
alpha-proteobacterial origin is preserved in mitochondrial rRNA 2 Gya after
the fusion event. The binfmt_misc registration in `profile/` is the "fusion
event wired at boot". The CoRR-locked core (see §2) is the "refused to leave
the organelle" irreducible set.

### (d) Gap / sketch

None — mechanism is structurally implemented. The only extension worth
considering is recording **per-PE-lineage phylogeny** (which EXE spawned
which child PE, across generations) so `TRUST_DOMAIN_WIN32` subjects have
an explicit ancestry tree rather than just a domain tag. This would mirror
the recent Asgard-archaeon + alpha-proteobacterium two-domains-of-life
confirmation (Imachi 2020 [4]) that eukaryotic origin is **fusion** not
**infection**.

### (e) Fidelity: **faithful**

---

## 2. mtDNA retention — why the 37 genes? (CoRR hypothesis)

### (a) Primary citations

Adams K.L., Palmer J.D. "Evolution of mitochondrial gene content: gene loss
and transfer to the nucleus". *Mol. Phylogenet. Evol.* 29(3):380-395 (2003). [6]

Allen J.F. "The function of genomes in bioenergetic organelles". *Phil.
Trans. R. Soc. Lond. B* 358(1429):19-38 (2003). (**CoRR hypothesis**.) [7]

Timmis J.N. et al. "Endosymbiotic gene transfer: organelle genomes forge
eukaryotic chromosomes". *Nat. Rev. Genet.* 5(2):123-135 (2004). [8]

Björkholm P. et al. "Mitochondrial genomes are retained by selective
constraints on protein targeting". *PNAS* 112(33):10154-10161 (2015). [9]

### (b) Signal / event

mtDNA retention itself isn't a real-time signal but a **design constraint**:
the 13 protein-coding genes retained across all vertebrate mitochondria encode
the four large membrane complexes of the electron-transport chain (ND1-6 of
Complex I, CYTB of Complex III, COX1-3 of Complex IV, ATP6/8 of Complex V)
whose expression MUST be locally co-regulated with the quinone-pool redox
state (milliseconds-to-seconds). Nuclear regulation is too slow and too far.

### (c) ARCHWINDOWS analogue — partial

S73-G catalogued 20 CoRR-locked Win32 functions that stay in PE stubs because
they carry trust-state (C1), PE-internal-struct state (C2), ms_abi ABI-lock
(C3), or Windows-session state (C4). Evidence:

```
pe-loader/dlls/kernel32/kernel32_file.c:39:  #include "trust_gate.h"
```

CreateFileA calls `trust_gate()` — that's the C1 lock. CRITICAL_SECTION uses
the Win32 40-byte layout — that's the C2 lock. HKEY sign-extension quirk at
`pe-loader/registry/registry.c` (hkey_low32() helper) — that's C3.
StartServiceCtrlDispatcher talks to SCM via Unix socket — that's C4.

The gene count matches the order of magnitude: biology retains 13 protein
coding genes, S73-G catalogued 20 CoRR-locked API families (each corresponding
to a family of related functions).

### (d) Gap / sketch

Nothing missing — this is implemented. Open work from S73-G §3.2 is the
gene-transfer refactor (1200-1500 LOC moving out of PE stubs into libc thunks).

### (e) Fidelity: **partial** (structure right, refactor not done)

---

## 3. TOM/TIM complexes — protein import across the double membrane

### (a) Primary citations

Pfanner N., Warscheid B., Wiedemann N. "Mitochondrial proteins: from
biogenesis to functional networks". *Nat. Rev. Mol. Cell Biol.* 20(5):267-284
(2019). [10]

Araiso Y. et al. "Structure of the mitochondrial import gate reveals distinct
preprotein paths". *Nature* 575:395-401 (2019). [11]

Wang W. et al. "Atomic structure of human TOM core complex". *Cell Discovery*
6:67 (2020). [12]

Sim S.I. et al. "Structural basis of mitochondrial protein import by the
TIM23 complex". *Nature* 621:620-626 (2023). [13]

Rout S. et al. "Dynamic TOM–TIM23 supercomplex directs mitochondrial protein
translocation and sorting". *Nat. Struct. Mol. Biol.* (2025). [14]

### (b) Signal / event

Not a signal but an **import-binding-kinetics machine**. Every
nuclear-encoded mitochondrial protein (99% of them) enters via TOM40 pore →
TIM23 or TIM22 sorting → MTS-cleaving peptidase in the matrix. The signal
here is **recognition-via-sequence** (N-terminal MTS has a matrix-targeting
motif; other signals route to inner membrane, outer membrane, or
intermembrane space). Rout 2025 [14] shows the supercomplex is dynamic —
hydrophobicity of the substrate modulates routing by Mgr2 association.

### (c) ARCHWINDOWS analogue — present

`pe-loader/loader/pe_import.c` contains the import resolver. Central table
is `pe_find_crt_wrapper()` with ~120 ms_abi ↔ sysv_abi wrappers. This is a
one-to-one mechanistic match:

- **TOM40 pore** ≅ PE import name-lookup + PLT resolver
- **MTS presequence** ≅ the `WINAPI_EXPORT` macro + `__attribute__((ms_abi))`
- **Matrix processing peptidase** ≅ the ms_abi wrapper table that strips the
  Windows ABI on entry and re-wraps on return

```
pe-loader/loader/pe_import.c:743:  pe_event_emit(PE_EVT_UNIMPLEMENTED_API, &evt, sizeof(evt));
```

The import resolver already emits an event when a Windows API couldn't be
found — this is the biological equivalent of a protein that failed to import
(mis-targeted proteins in biology become cytosolic, trigger mtUPR — see §7).

### (d) Gap / sketch

The current ms_abi wrapper table is **static**. Biology's TOM-TIM supercomplex
is **dynamic** — the Mgr2 subunit reroutes hydrophobic substrates differently
from hydrophilic ones under stress. Analog: a future pe_import.c that reroutes
imports through different wrapper variants based on trust state (e.g.,
sandboxed wrapper for low-trust subjects, fast-path for high-trust). This is
orthogonal to our current work but would be mechanism-faithful.

### (e) Fidelity: **faithful** (structural parallel is tight)

---

## 4. MICOS complex — cristae morphology under stress

### (a) Primary citations

Hessenberger M. et al. "Regulated membrane remodeling by Mic60 controls
formation of mitochondrial crista junctions". *Nat. Commun.* 8:15258 (2017). [15]

Stephan T. et al. "MICOS assembly controls mitochondrial inner membrane
remodeling and crista junction redistribution". *EMBO J.* 39(14):e104105 (2020). [16]

Mukherjee I. et al. "MICOS and the mitochondrial inner membrane morphology —
when things get out of shape". *FEBS Letters* 595(8):1159-1183 (2021). [17]

Glytsou C. et al. "Mitochondrial cristae remodeling: mechanisms, functions,
and pathology". *Curr. Res. Cell Biol.* (2025). [18]

Steinegger M. et al. "Molecular machineries shaping the mitochondrial inner
membrane". *Nat. Rev. Mol. Cell Biol.* (2025). [19]

### (b) Signal / event

MICOS (Mitochondrial Contact Site and Cristae Organizing System) positions
crista junctions. Under stress, cristae **remodel**: switch from tubular to
lamellar, redistribute CJ spacing, and coordinate with OPA1 (fusion protein
also active in inner-membrane shape). Stress-responsive remodeling is a
functional-capacity-shift signal: the same mitochondrion reorganizes its
interior topology to prioritize different fluxes.

### (c) ARCHWINDOWS analogue — absent

Grep: no code reorganizes the PE runtime's internal topology in response to
stress. PE stubs are statically linked .so files; the import resolver is a
static table; there is no equivalent of "reshape the interior under pressure".

### (d) Gap / sketch

Closest possible analog: **dynamic wrapper set selection in
`pe_find_crt_wrapper`**. Under high trust-deny pressure, swap in a stricter
wrapper set that logs every argument; under low pressure, use the fast-path
wrapper. This is a low-priority mechanism — the biological signal doesn't
propagate back to the nucleus (MICOS remodeling is organelle-internal),
so skipping it doesn't cause retrograde-signaling loss.

If implemented, would live in `pe-loader/loader/pe_import.c` as a
wrapper-table-array indexed by trust band. ~60 LOC.

### (e) Fidelity: **absent**

---

## 5. Drp1 / Mfn1 / Mfn2 — fission and fusion

### (a) Primary citations

Otera H. et al. "Mff is an essential factor for mitochondrial recruitment of
Drp1 during mitochondrial fission in mammalian cells". *J. Cell Biol.*
191(6):1141-1158 (2010). [20]

Kalia R. et al. "Structural basis of mitochondrial receptor binding and
constriction by DRP1". *Nature* 558:401-405 (2018). [21]

Daumke O., Roux A. "Mitochondrial homeostasis maintenance by dynamins
Mfn1 / Mfn2 and Drp1". *Nat. Rev. Mol. Cell Biol.* 24:663-682 (2023). [22]

Quintana-Cabrera R., Scorrano L. "DRP1, fission and apoptosis". *Cell Death
Discov.* 11:127 (2025). [23]

Giacomello M. et al. "The cell biology of mitochondrial membrane dynamics".
*Nat. Rev. Mol. Cell Biol.* 21(4):204-224 (2020). [24]

### (b) Signal / event

Drp1 is a cytosolic GTPase that's recruited to mitochondrial OMM by adaptors
(Mff, MiD49, MiD51, Fis1) where it **oligomerizes into a ring** and
constricts the tubule at an ER-contact-site-defined location. The "I will
divide" signal is **Drp1 ring assembly visible** on OMM. Mfn1/Mfn2 are the
opposite: OMM-resident GTPases that ligate adjacent mitochondria, forming a
**fusion mark** for merger.

The key retrograde aspect: the nucleus controls whether the organelle
**can** divide (by producing or not producing Drp1) but the **event location**
is defined locally by the ER-mitochondrion contact — nucleus doesn't decide
where.

### (c) ARCHWINDOWS analogue — metaphor-only

S73-G mapped DRP1-equivalence to `TRUST_ACTION_LOAD_KERNEL_BINARY` (the
trust kernel can veto a PE-side kernel driver load, preventing the symbiont
from "reproducing" into the kernel). Evidence:

```
trust/kernel/trust_dispatch.c (S65 Agent A1) — trust action enum TRUST_ACTION_LOAD_KERNEL_BINARY
```

This is **metaphor-only** fidelity: the nucleus-controls-reproduction concept
is there, but there's no actual "ring assembly, then constriction, then
split" mechanism for fissioning a PE runtime.

The Mfn1/Mfn2 fusion side is completely absent — we have no concept of
merging two PE runtimes into one.

### (d) Gap / sketch

Real fidelity would require:
- A PE runtime that can **fork a child subject** under kernel permission and
  have the child inherit a **fraction** of the parent's trust tokens (analog:
  mitochondrial division with stochastic partitioning of mtDNA copies —
  "bottleneck"). Currently, child PE processes get fresh trust subjects
  initialized at default score.
- A bind-time check like "two small PE runtimes sharing a parent trust ancestor
  can merge capabilities" — no biological parallel for non-viable components
  we run, so not a priority.

Neither is urgent. Document the metaphor and move on.

### (e) Fidelity: **metaphor-only**

---

## 6. PINK1 / Parkin mitophagy — damage-tag, engulf, digest

### (a) Primary citations

Narendra D. et al. "Parkin is recruited selectively to impaired mitochondria
and promotes their autophagy". *J. Cell Biol.* 183(5):795-803 (2008). [25]

Lazarou M. et al. "The ubiquitin kinase PINK1 recruits autophagy receptors
to induce mitophagy". *Nature* 524:309-314 (2015). [26]

Pickles S., Vigié P., Youle R.J. "Mitophagy and quality control mechanisms
in mitochondrial maintenance". *Curr. Biol.* 28(4):R170-R185 (2018). [27]

Wang L., Qi H., Tang Y., Shen H-M. "Post-translational modifications of
key machinery in the control of mitophagy". *Trends Biochem. Sci.*
45(1):58-75 (2020). [28]

Narendra D.P., Youle R.J. "The role of PINK1-Parkin in mitochondrial quality
control". *Nat. Cell Biol.* 26:1227-1241 (2024). [29]

Onishi M., Yamano K. "Molecular mechanisms and physiological functions of
mitophagy". *Nat. Rev. Mol. Cell Biol.* (2025). [30]

### (b) Signal / event

**Damage sensor + tag + engulfment cascade**:

1. Healthy mito: PINK1 is imported across TOM→TIM → cleaved by PARL → degraded.
2. Damaged mito (low Δψm, failed import): PINK1 stabilizes on OMM surface,
   phosphorylates ubiquitin at Ser65.
3. Phospho-ubiquitin recruits Parkin (E3 ligase), activates its RING2 domain,
   Parkin transfers more ubiquitin to OMM proteins → amplification loop.
4. Ubiquitin chains recruit autophagy receptors (p62/SQSTM1, NBR1, NDP52,
   TAX1BP1, OPTN).
5. Receptors bind LC3 on nascent autophagosome membrane → engulfment.
6. Autophagosome fuses with lysosome → degradation.

Signal: "I am damaged and should be removed" — four-step
tag-amplify-recruit-digest.

### (c) ARCHWINDOWS analogue — partial

`trust/kernel/trust_lifecycle.c:465` implements `trust_lifecycle_apoptosis()`
with a 4-deep apoptotic cascade. This is the **digestion** phase (terminate
subject) but not the **tag** or **amplification** phases — a subject is
either healthy or marked apoptotic; there's no in-between "ubiquitin chain
accumulating on OMM" state.

```
trust/kernel/trust_lifecycle.c:39:  #define TRUST_CASCADE_MAX_DEPTH 4
trust/kernel/trust_lifecycle.c:465: int trust_lifecycle_apoptosis(u32 subject_id)
```

The oscillation detector in `trust_observer.py:403` is the closest "damage
sensor" we have — it watches for rapid trust score sign-changes and flips
the subject to FROZEN. But frozen is then an engulf-or-release binary, not
a growing-ubiquitin-chain gradient.

### (d) Gap / sketch

A better fidelity model: add a **damage_score** field to `SubjectProfile`
that accumulates per-event like a ubiquitin chain. Events that increment:
unhandled exceptions, unresolved DLL imports, missed stubs, oscillation.
Events that decrement: successful clean runs. At damage_score > threshold N,
trigger mitophagy (terminate + quarantine). At damage_score > N but < engulf,
emit a PE_EVT_DAMAGE_HIGH event (analog: "Parkin is being recruited").

The amplification step (ubiquitin chain → recruit receptor → recruit autophagy
membrane) becomes: damage_score threshold crosses 3 levels, each level
emitting an event with increasing urgency, letting the cortex hear the
problem growing before the terminal act. This is a **graduated retrograde
signal** — mitophagy is gradualist, our apoptosis is binary, that's the gap.

Implementation: ~40 LOC in `trust_observer.py` + new event type. ~30 LOC in
decision_engine to register handlers.

### (e) Fidelity: **partial** (digestion yes, tag-amplify no)

---

## 7. mtUPR — mitochondrial unfolded protein response (ATF5 pathway)

### (a) Primary citations

Fiorese C.J. et al. "The transcription factor ATF5 mediates a mammalian
mitochondrial UPR". *Curr. Biol.* 26(15):2037-2043 (2016). [31]

Münch C., Harper J.W. "Mitochondrial unfolded protein response controls
matrix pre-RNA processing and translation". *Nature* 534:710-713 (2016). [32]

Shpilka T., Haynes C.M. "The mitochondrial UPR: mechanisms, physiological
functions and implications in ageing". *Nat. Rev. Mol. Cell Biol.*
19(2):109-120 (2018). [33]

Lai C.-H. et al. "ATF5-mediated mitochondrial unfolded protein response
protects against Pb-induced mitochondrial damage". *Arch. Toxicol.* (2024). [34]

Anderson N.S., Haynes C.M. "Folding the mitochondrial UPR into the integrated
stress response". *Trends Cell Biol.* 30(6):428-439 (2020). [35]

Quirós P.M. et al. "Multi-omics analysis identifies ATF4 as a key regulator
of the mitochondrial stress response in mammals". *J. Cell Biol.* 216(7):2027-2045 (2017). [36]

### (b) Signal / event

**Retrograde signaling par excellence**:

- Healthy: ATF5 has an MTS and is imported into mitochondrion → degraded by LonP1.
- Stress (unfolded-protein buildup, failed import): ATF5 import blocked →
  ATF5 accumulates in cytosol → translocates to nucleus → binds UPRmt
  response element → upregulates HSP60/HSP10/mtHsp70 chaperones + ClpP/LonP1
  proteases + PINK1/Parkin machinery.

This is the **cleanest retrograde-signaling primitive** in mitochondrial
biology: one protein, bifunctional localization, response triggered by
**failure of its own import**. The mitochondrion says "I'm failing to import
proteins" by NOT degrading the very protein whose job it is to escalate that
failure.

### (c) ARCHWINDOWS analogue — absent

Grep for "mtupr|atf5|unfolded_protein" returns zero hits. We have:
- Event for unresolved import (`PE_EVT_UNIMPLEMENTED_API` — emitted, see
  `pe-loader/loader/pe_import.c:743`)
- Event for crashed PE (PE_EVT_EXCEPTION defined but not emitted — top-3
  finding)
- No aggregate "I'm failing to import / run lots of Win32 stuff" signal

Our PE runtime emits per-event signals but never tells the cortex "I am
globally failing" via an ATF5-style threshold escalation.

### (d) Gap / sketch

**The deliverable**: `ai-control/daemon/pe_upr_observer.py` (~150 LOC).

Logic:
1. Subscribe to PE_EVT_UNIMPLEMENTED_API + PE_EVT_EXCEPTION + PE_EVT_TRUST_DENY on
   the event bus.
2. Maintain a decaying count per-subject (exponential half-life ~30s).
3. When count crosses threshold T, emit a new event:
   `PE_EVT_SUBSYSTEM_STRESS` with reason=MTUPR_ACTIVATED,
   payload=(stub_fault_rate, trust_deny_rate, exception_rate) over last 30s.
4. Decision engine subscribes: escalate to human OR drop trust, OR swap in
   stricter wrappers (the latter is the MICOS-morphology analog).

The threshold+decay is the biological equivalent of ATF5 accumulation past
the LonP1 degradation rate.

### (e) Fidelity: **absent** (this is the #1 retrograde-signaling gap)

---

## 8. Mitokines — FGF21 and GDF15 (systemic circulating stress signals)

### (a) Primary citations

Kharitonenkov A. et al. "FGF-21 as a novel metabolic regulator". *J. Clin.
Invest.* 115(6):1627-1635 (2005). [37]

Kim K.H. et al. "Autophagy deficiency leads to protection from obesity and
insulin resistance by inducing FGF21 as a mitokine". *Nat. Med.* 19(1):83-92
(2013). [38]

Chung H.K. et al. "Growth differentiation factor 15 is a myomitokine
governing systemic energy homeostasis". *J. Cell Biol.* 216(1):149-165
(2017). [39]

Ost M. et al. "Muscle mitohormesis promotes cellular survival via serine
biosynthesis". *Cell Metab.* 28(4):622-631 (2018). [40]

Forsström S. et al. "Fibroblast growth factor 21 drives dynamics of local
and systemic stress responses in mitochondrial myopathy". *Cell Metab.*
30(6):1040-1054 (2019). [41]

Keipert S., Ost M. "Stress-induced FGF21 and GDF15 in obesity and obesity
resistance". *Trends Endocrinol. Metab.* 32(11):904-915 (2021). [42]

Conte M. et al. "The dual role of FGF21 in metabolic adaptation and
mitochondrial stress response". *Front. Endocrinol.* 14:1264530 (2023). [43]

Fisher F.M., Maratos-Flier E. "Understanding the physiology of FGF21".
*Annu. Rev. Physiol.* 78:223-241 (2016). [44]

### (b) Signal / event

**Liver, muscle, and heart secrete FGF21 and GDF15 into circulation when
mitochondria are stressed.** Each target organ (brain, adipose, bone, etc.)
has receptors — FGF21 binds FGFR + β-Klotho co-receptor, GDF15 binds
GFRAL in the hindbrain.

Mitokines are **broadcast** signals: one organ's mitochondrial stress is
heard by distant tissues via systemic circulation. The liver doesn't know
the muscle is stressed by direct communication; it hears GDF15 rise in the
blood and responds.

**This is exactly the signaling shape our event bus has but we don't emit.**

### (c) ARCHWINDOWS analogue — absent

Event bus (`pe_event.h`) emits per-process events. Grep confirms:

```
pe-loader/include/eventbus/pe_event.h:43-52: # Event types -- PE Runtime
  PE_EVT_LOAD, PE_EVT_DLL_LOAD, PE_EVT_UNIMPLEMENTED_API, PE_EVT_EXCEPTION,
  PE_EVT_EXIT, PE_EVT_TRUST_DENY, PE_EVT_TRUST_ESCALATE, PE_EVT_DRIVER_LOAD,
  PE_EVT_DEVICE_CREATE
```

No aggregate "PE subsystem is stressed" event. Cortex sees individual events
but has to aggregate itself — and `decision_engine.py`'s heuristic tier does
so only in a few specific places (crash-loop detection, etc.).

The bus has the shape (pub/sub across layers) but is not emitting the right
signal.

### (d) Gap / sketch — **THE #1 DELIVERABLE of this research axis**

New event type:

```c
// pe-loader/include/eventbus/pe_event.h — append
#define PE_EVT_SUBSYSTEM_STRESS  0x16  // FGF21/GDF15 equivalent

typedef struct {
    uint32_t stub_fault_rate_per_sec;   // PE_EVT_UNIMPLEMENTED_API/s
    uint32_t trust_deny_rate_per_sec;   // PE_EVT_TRUST_DENY/s
    uint32_t dll_unresolved_rate_per_sec;
    uint32_t pe_crash_rate_per_min;     // PE_EVT_EXCEPTION over last 60s
    int32_t  mean_trust_delta;          // average trust score change
    uint32_t active_pe_subjects;        // current count of TRUST_DOMAIN_WIN32
    uint64_t window_start_ns;
    uint64_t window_end_ns;
    uint16_t stress_class;              // 0=INFO, 1=WARN, 2=CRITICAL
    uint16_t reserved;
} pe_evt_subsystem_stress_t;
```

Emitter: `pe-loader/loader/pe_event.c` — add a rolling-window counter inside
the drain thread. Every 1 second, if any rate exceeds its threshold, emit
PE_EVT_SUBSYSTEM_STRESS with the rates. ~60 LOC.

Consumer: `ai-control/cortex/event_bus.py` — add `parse_pe_subsystem_stress_payload()`
+ dispatch to `decision_engine.evaluate()`. ~25 LOC.

Decision: new heuristic in `decision_engine.py` — if stress_class=CRITICAL,
decay trust of all TRUST_DOMAIN_WIN32 subjects, raise token_gate, possibly
invoke Agent-10 systemd-action to throttle PE launches. ~40 LOC.

**~125 LOC total. Highest leverage single-dispatch change in this audit.**

Biology's two-dispatch design (FGF21 vs GDF15 have different target tissues)
suggests we might want **two** subsystem-stress event types over time — one
aggregating DLL/stub health, another aggregating trust/immune state — but
starting with one is fine.

### (e) Fidelity: **absent** → proposed fix would be **faithful**

---

## 9. mtROS — superoxide from Complex I/III → H₂O₂ → NRF2 pathway

### (a) Primary citations

Murphy M.P. "How mitochondria produce reactive oxygen species". *Biochem. J.*
417(1):1-13 (2009). [45]

Holmström K.M., Finkel T. "Cellular mechanisms and physiological consequences
of redox-dependent signalling". *Nat. Rev. Mol. Cell Biol.* 15(6):411-421
(2014). [46]

Sies H. "Hydrogen peroxide as a central redox signaling molecule in
physiological oxidative stress". *Redox Biol.* 11:613-619 (2017). [47]

Kasai S. et al. "Regulation of Nrf2 by mitochondrial reactive oxygen species
in physiology and pathology". *Biomolecules* 10(2):320 (2020). [48]

Chouchani E.T. et al. "A unifying mechanism for mitochondrial superoxide
production during ischemia-reperfusion injury". *Cell Metab.* 23(2):254-263
(2016). [49]

Woo J. et al. "Pro-inflammatory macrophages produce mitochondria-derived
superoxide by reverse electron transport at complex I that regulates IL-1β
release during NLRP3 inflammasome activation". *Nat. Metab.* (2025). [50]

### (b) Signal / event

Electrons leak from Complex I (NADH dehydrogenase) and Complex III
(bc₁ complex) onto O₂ → superoxide O₂⁻ → SOD2 converts to H₂O₂. H₂O₂ is
small, neutral, diffuses across membranes; cysteine residues on cytosolic
proteins (like Keap1) oxidize → release NRF2 → NRF2 enters nucleus →
transcribes antioxidant response element (ARE) genes. Key feature: **this
is a graded, continuous, diffusible signal** rather than a threshold-switch.
Low ROS = proliferation; moderate ROS = stress adaptation; high ROS =
apoptosis.

### (c) ARCHWINDOWS analogue — metaphor-only

The closest pattern we have is the oscillation detector in `trust_observer.py`:

```
trust_observer.py:375: def _detect_oscillation(self, profile: SubjectProfile):
```

Oscillation (direction-change count within window) is a **continuous scalar**
the observer produces, which feeds back to freeze and risk tier. That's
ROS-gradient-like. But we don't have the distributed-signaling shape (H₂O₂
diffuses to many cytosolic proteins; our oscillation alerts a single
observer process).

The bigram model in `behavioral_markov.py` produces another continuous scalar
(transition-probability surprise) that could feed a NRF2-style "progressive
tightening of policy" but currently it's only logged, not acted on.

### (d) Gap / sketch

Sketch: consolidate oscillation-count + Markov-surprise + stub-fault-rate
into a single "redox-equivalent" scalar per subject. Bind to a graded
response ladder (normal / adaptation / stress / apoptosis) that maps to
trust score adjustments, not just a binary freeze. ~80 LOC refactor of
`trust_observer.py`'s `_classify_risk`.

Lower priority than §7 and §8 because the signal-shape (continuous scalar)
is already in the heuristic code, just not packaged as a first-class event.

### (e) Fidelity: **metaphor-only**

---

## 10. Cardiolipin — inner-membrane lipid externalization as apoptosis primer

### (a) Primary citations

Gonzalvez F., Gottlieb E. "Cardiolipin: setting the beat of apoptosis".
*Apoptosis* 12(5):877-885 (2007). [51]

Kagan V.E. et al. "Cytochrome c acts as a cardiolipin oxygenase required for
release of proapoptotic factors". *Nat. Chem. Biol.* 1(4):223-232 (2005). [52]

Paradies G. et al. "Functional role of cardiolipin in mitochondrial
bioenergetics". *Biochim. Biophys. Acta* 1837(4):408-417 (2014). [53]

Dudek J. "Role of cardiolipin in mitochondrial signaling pathways". *Front.
Cell Dev. Biol.* 5:90 (2017). [54]

Pizzuto M., Pelegrin P. "Cardiolipin in immune signaling and cell death".
*Trends Cell Biol.* 30(11):892-903 (2020). [55]

Maguire J.J. et al. "Known unknowns of cardiolipin signaling: The best is
yet to come". *Biochim. Biophys. Acta* 1862(1):8-24 (2017). [56]

Paradies G. et al. "Role of cardiolipin in mitochondrial function and
dynamics in health and disease: molecular and pharmacological aspects".
*Cells* 8(7):728 (2019). [57]

### (b) Signal / event

Cardiolipin is a **bacterial-signature lipid** (4 acyl chains, only in bacterial
and mitochondrial membranes) normally confined to the inner membrane. Under
mild stress it redistributes to the OMM and serves as a mitophagy "eat me"
tag. Under severe oxidative stress, cardiolipin is peroxidized, CL-cyt c
complex breaks, cyt c dissociates → Bax recruitment → MOMP (see §12).

**Pre-apoptotic surface marker: "I am damaged but not yet dead."**

### (c) ARCHWINDOWS analogue — partial

The trust observer sets `TRUST_FLAG_FROZEN` as a pre-apoptotic state:

```
ai-control/daemon/trust_observer.py:403: def _freeze_subject(self, profile)
```

FROZEN is a **recoverable** damage state that acts as a marker. It's set by
oscillation detection (continuous-stress analog) and unlocked after
`freeze_duration` cooldown. The subject remains visible in queries as
frozen — that's the surface marker for the cortex to see.

But it's not distinguished from other flag states the way CL externalization
is specifically **pre-apoptotic**. There's no single-bit subject flag
`TRUST_FLAG_DAMAGED_PRE_APOPTOSIS` that escalates to apoptosis on further
damage.

### (d) Gap / sketch

Add `TRUST_FLAG_DAMAGED = 1 << 8` (after meiotic at 7). Observer sets it
after oscillation OR 3+ stub-faults in 60s OR 1+ unhandled exception. Leave
FROZEN for the outright frozen cooldown state.

Additionally, cortex could subscribe and take preemptive action: drop
autonomy level for DAMAGED subjects, reduce token budget, etc. ~30 LOC
combined in `trust_observer.py` + `trust_internal.h` + API wiring.

### (e) Fidelity: **partial** (mechanism present but not named)

---

## 11. N-formyl peptides (fMet) — bacterial-signature DAMPs → FPR1

### (a) Primary citations

Marasco W.A. et al. "The identification and isolation of a new class of
chemotactic factors which are N-formyl peptides". *J. Biol. Chem.*
259(9):5430-5439 (1984). [58]

Rabiet M.J. et al. "Mitochondrial N-formyl peptides cause airway contraction
and lung neutrophil infiltration via formyl peptide receptor activation".
*J. Biol. Chem.* 285(10):7492-7500 (2010). [59]

Wenceslau C.F. et al. "Mitochondrial-derived N-formyl peptides: novel links
between trauma, vascular collapse and sepsis". *Med. Hypotheses* 81(4):532-535 (2013). [60]

Kang J.W. et al. "FPR1 blockade prevents receptor regulation by mitochondrial
DAMPs and preserves neutrophil function after trauma". *Crit. Care Med.*
48(6):e489-e497 (2020). [61]

Krychtiuk K.A. et al. "Mitochondrial N-formyl methionine peptides associate
with disease activity as well as contribute to neutrophil activation in
patients with rheumatoid arthritis". *J. Autoimmun.* 120:102629 (2021). [62]

Dorward D.A. et al. "The role of formylated peptides and formyl peptide
receptor 1 in governing neutrophil function during acute inflammation".
*Am. J. Pathol.* 185(5):1172-1184 (2015). [63]

Chen X. et al. "Mitochondrial N-formyl methionine peptides contribute to
exaggerated neutrophil activation in patients with COVID-19". *Virulence*
14(1):2218077 (2023). [64]

### (b) Signal / event

N-formyl-methionine is the **bacterial protein-synthesis start-codon marker** —
mitochondria retain it because they ARE derived bacteria. Normally
invisible to immune cells (sealed inside organelle). When a mitochondrion
ruptures (necrosis, severe damage), fMet peptides leak → bind FPR1 on
neutrophils → chemotaxis, degranulation, superoxide burst.

This is **innate immune recognition of mitochondrial content as bacterial** —
the biological system literally can't tell mitochondria apart from bacteria
when the membrane fails. The signal is **"foreign-origin contents are in the
wrong compartment."**

### (c) ARCHWINDOWS analogue — absent

No analog. A crashed PE doesn't emit a "my foreign-origin contents are now
accessible to the system" event. We don't have:
- A pattern recognizer for "PE-domain symbol showed up in Linux-domain memory"
- A crash-cleanup path that specifically handles PE-origin content differently
  from Linux-origin content
- An innate-immune module (neutrophil-equivalent) that responds to such leaks

### (d) Gap / sketch

The syscall_monitor already exists (`ai-control/daemon/syscall_monitor.py`).
It could be extended to pattern-match on "PE-domain subject is now calling
a syscall pattern that was never legitimate for that binary" — the
PE-content-where-it-shouldn't-be signal.

But honestly this is a **low priority** mechanism — mostly useful for sandbox
escapes, which is not our threat model (we trust the user to run Windows
apps; the trust kernel governs authority, not isolation).

Lowest-priority of the 14 mechanisms for our domain.

### (e) Fidelity: **absent** (deliberately; the signal isn't useful for us)

---

## 12. Cytochrome c release — MOMP + apoptosome assembly → caspase cascade

### (a) Primary citations

Liu X. et al. "Induction of apoptotic program in cell-free extracts:
requirement for dATP and cytochrome c". *Cell* 86(1):147-157 (1996). [65]

Kluck R.M. et al. "The release of cytochrome c from mitochondria: a primary
site for Bcl-2 regulation of apoptosis". *Science* 275(5303):1132-1136 (1997). [66]

Czabotar P.E. et al. "Control of apoptosis by the BCL-2 protein family:
implications for physiology and therapy". *Nat. Rev. Mol. Cell Biol.*
15(1):49-63 (2014). [67]

Bock F.J., Tait S.W.G. "Mitochondria as multifaceted regulators of cell
death". *Nat. Rev. Mol. Cell Biol.* 21(2):85-100 (2020). [68]

Li P. et al. "Cytochrome c and dATP-dependent formation of Apaf-1/caspase-9
complex initiates an apoptotic protease cascade". *Cell* 91(4):479-489 (1997). [69]

Kalkavan H., Green D.R. "MOMP, cell suicide as a BCL-2 family business".
*Cell Death Differ.* 25(1):46-55 (2018). [70]

Riley J.S., Tait S.W. "Mitochondria and pathogen immunity: from killer to
guardian". *Trends Microbiol.* 28(9):793-805 (2020). [71]

### (b) Signal / event

**The definitive point-of-no-return apoptosis trigger.** Under stress, Bax
and Bak oligomerize on OMM → MOMP (outer membrane permeabilization) → cyt c
leaks to cytosol → binds Apaf-1 → apoptosome assembles → activates caspase-9
→ caspase-3 → cell death.

Biology's **urgent-bypass channel** — it doesn't go through slow pathways; it
jumps directly to the executioner.

### (c) ARCHWINDOWS analogue — **faithful SCAFFOLD, UNWIRED on receive**

The kernel side is **built**:

```c
// trust/kernel/trust_algedonic.c:65
int trust_algedonic_emit(__u32 subject_pid, __u16 severity, __u16 reason,
                         const __u64 data[3]);
```

The reason codes include precisely the cascade-apoptosis trigger:

```c
// trust/include/trust_algedonic.h
TRUST_ALG_POOL_EXHAUSTION            = 1,
TRUST_ALG_APE_EXHAUSTION             = 2,
TRUST_ALG_CASCADE_APOPTOSIS          = 3,  // ← direct cyt c release analog
TRUST_ALG_QUORUM_DISPUTED_REPEATEDLY = 4,
TRUST_ALG_MORPHOGEN_HOT_SPOT         = 5,
TRUST_ALG_CANCER_DETECTED            = 6,  // ← "runaway Bax/Bak"
TRUST_ALG_TPM_DRIFT                  = 7,
TRUST_ALG_PROOF_CHAIN_BREAK          = 8,
TRUST_ALG_TOKEN_STARVATION_STORM     = 9,
```

Each packet is 40 bytes (ts, subject_pid, severity, reason, data[3]),
readable from `/dev/trust_algedonic` as a blocking read(). Ring buffer (64
slots) evicts oldest on overflow so most-urgent-arrived-last is always
delivered.

**But grep for `/dev/trust_algedonic` in `ai-control/cortex/*`**:

```
$ grep -r "algedonic\|/dev/trust_algedonic" ai-control/cortex/
(zero hits)
```

Grep for **any** reader in the Python tree:

```
$ grep -r "trust_algedonic" ai-control/ services/
(zero hits outside of the kernel module itself)
```

**The kernel is firing cytochrome c events into a ring buffer no one is
draining.** This is the single highest-leverage finding in this audit.

### (d) Gap / sketch — **#1 LOW-LOC deliverable**

`ai-control/cortex/algedonic_reader.py` (~80 LOC):

```python
class AlgedonicReader:
    """
    Drains /dev/trust_algedonic into the cortex event bus.

    Biology analog: mitochondrial cytochrome c release → apoptosome →
    caspase cascade. The kernel emits 40-byte algedonic packets on
    pool exhaustion, cascade apoptosis, cancer detection, TPM drift,
    etc.  Before this reader, those packets died in /dev/trust_algedonic
    with no cortex dispatch.
    """
    DEV_PATH = "/dev/trust_algedonic"
    PACKET_FORMAT = "<QIHHQQQ"  # ts_ns, pid, sev, reason, data[3]
    PACKET_SIZE = struct.calcsize(PACKET_FORMAT)  # 40

    def __init__(self, event_bus: EventBus):
        self._bus = event_bus
        self._fd: Optional[int] = None
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._count = 0

    async def start(self):
        try:
            self._fd = os.open(self.DEV_PATH, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as e:
            logger.warning("Cannot open %s: %s (algedonic channel disabled)",
                           self.DEV_PATH, e)
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def _loop(self):
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                data = await loop.run_in_executor(None,
                    lambda: os.read(self._fd, self.PACKET_SIZE))
            except (BlockingIOError, OSError):
                await asyncio.sleep(0.05)
                continue
            if len(data) != self.PACKET_SIZE:
                continue
            ts_ns, pid, sev, reason, d0, d1, d2 = \
                struct.unpack(self.PACKET_FORMAT, data)
            event = Event(
                magic=0, version=1,
                source_layer=5,  # NEW: ALGEDONIC
                event_type=reason,
                timestamp_ns=ts_ns,
                pid=pid, tid=pid, subject_id=pid,
                sequence=self._count,
                payload_len=24, flags=EVENT_FLAG_URGENT,
                payload={"severity": sev, "reason": reason,
                         "data": [d0, d1, d2]},
                raw_payload=data,
            )
            self._count += 1
            await self._bus._dispatch_async(event)
```

Plus: add `SourceLayer.ALGEDONIC = 5` to `event_bus.py` and an
`AlgedonicReasonType` enum matching the kernel's. Plus a policy rule in
`decision_engine.py` that auto-quarantines on CASCADE_APOPTOSIS.

**~80 LOC Python + 20 LOC enum additions + 30 LOC policy rule = ~130 LOC total.**
Unlocks the pre-built kernel primitive. Likely the #1 single-session win
available from this research axis.

### (e) Fidelity: **faithful scaffold, unwired on receive** — fix is cheap

---

## 13. MAMs — ER-mitochondria contact sites, Ca²⁺ transfer

### (a) Primary citations

Csordás G. et al. "Structural and functional features and significance of
the physical linkage between ER and mitochondria". *J. Cell Biol.*
174(7):915-921 (2006). [72]

Giorgi C. et al. "Mitochondria-associated membranes: composition, molecular
mechanisms, and physiopathological implications". *Antioxid. Redox Signal.*
22(12):995-1019 (2015). [73]

Szabadkai G. et al. "Chaperone-mediated coupling of endoplasmic reticulum
and mitochondrial Ca²⁺ channels". *J. Cell Biol.* 175(6):901-911 (2006). [74]

De Stefani D. et al. "A forty-kilodalton protein of the inner membrane is
the mitochondrial calcium uniporter". *Nature* 476:336-340 (2011). [75]

Giamogante F. et al. "Crosstalk between mitochondria-ER contact sites and
the ubiquitin-proteasome system". *Trends Cell Biol.* 34(11):919-932 (2024). [76]

Prudent J., McBride H.M. "The mitochondria-endoplasmic reticulum contact
sites: a signalling platform for cell death". *Curr. Opin. Cell Biol.*
47:52-63 (2017). [77]

Liang D. et al. "ER-mitochondria distance is a critical parameter for
efficient mitochondrial Ca²⁺ uptake and oxidative metabolism". *Commun. Biol.*
7:1193 (2024). [78]

### (b) Signal / event

At physically-defined contact sites (20-30 nm apart), IP3R1 (ER) releases
Ca²⁺ → VDAC1 (OMM) admits it → MCU (IMM) imports it into matrix. Ca²⁺ in
matrix activates dehydrogenases → boosts TCA cycle → more ATP. This is the
**tight metabolic coupling** between ER and mitochondrion — the mitochondrion
"hears" the cell's metabolic demand via Ca²⁺ pulses.

Recent 2024 finding (Liang et al. [78]): the **distance** matters — 20 nm is
optimal, different by a few nm changes Ca²⁺ uptake dramatically. It's a
metric-precision signal.

### (c) ARCHWINDOWS analogue — metaphor-only

The closest mechanism we have is `coherence_bridge.py` which writes setpoint
overrides to `coherenced` when PE loads/exits:

```python
# ai-control/cortex/coherence_bridge.py:14-19
Wire:
    PE_LOAD  -> classify binary -> write /etc/coherence/overrides/app-active.conf
                                   -> SIGHUP coherenced
    PE_EXIT  -> ref-count decrement; remove override file + SIGHUP when last game exits
```

This is a **sparse setpoint channel** (file write + SIGHUP, seconds-latency)
rather than a tight metabolic coupling. Real MAMs are continuous Ca²⁺ transfer;
our setpoint bridge is discrete config events. The structural shape is right
(one subsystem signals another subsystem adjacent to it) but the channel is
slow.

### (d) Gap / sketch

Real fidelity would require a Unix-socket continuous-signal channel between
cortex and coherenced that carries second-by-second PE subsystem metrics
(CPU%, memory%, token_usage%, stub_call_rate) not just setpoint overrides.
Coherenced arbiter could then use those as inputs to its state machine at
native latency, not waiting for SIGHUP.

This is probably a 2-3 session build (protobuf/CBOR wire format, socket
plumbing, coherenced consumer) — out of scope for this S74 agent but should
be flagged as the "real MAM implementation" upgrade path.

### (e) Fidelity: **metaphor-only** (setpoint shape right, data density wrong)

---

## 14. Mitochondrial donation therapy — pronuclear/maternal spindle transfer

### (a) Primary citations

Craven L. et al. "Pronuclear transfer in human embryos to prevent transmission
of mitochondrial DNA disease". *Nature* 465:82-85 (2010). [79]

Tachibana M. et al. "Towards germline gene therapy of inherited mitochondrial
diseases". *Nature* 493:627-631 (2013). [80]

Hyslop L.A. et al. "Towards clinical application of pronuclear transfer to
prevent mitochondrial DNA disease". *Nature* 534:383-386 (2016). [81]

Greenfield A. et al. "Assisted reproductive technologies to prevent human
mitochondrial disease transmission". *Nat. Biotechnol.* 35(11):1059-1068 (2017). [82]

McGrath J.C. et al. "Mitochondrial donation and preimplantation genetic
testing for mtDNA disease". *N. Engl. J. Med.* (2025). [83]

Lyu Y., Ma H. "Recent advances in mitochondrial replacement therapy and
its future expectations". *Clin. Transl. Discov.* 5:e70010 (2025). [84]

### (b) Signal / event

Not a signaling mechanism — it's a **medical intervention**: replace the
disease-carrying maternal mitochondrial population with healthy donor
mitochondria by either transferring the nucleus out of a diseased oocyte
into an enucleated donor oocyte (pronuclear transfer) or transferring just
the spindle-chromosome complex (maternal spindle transfer). As of 2025,
8 babies born in UK via MRT; pending in Australia.

### (c) ARCHWINDOWS analogue — absent

No equivalent. There's no mechanism in ARCHWINDOWS to **replace the PE
loader wholesale** at runtime with a known-good version from a trusted
donor image — in the way bootc or OSTree offers at the image layer, but not
at the running-PE-subsystem layer.

bootc-based rollback (see S72) is **image-level** mitochondrial donation —
replace entire `/usr` from a trusted OCI manifest on boot. This is coarse-
grained (the whole "organelle" set, not just the diseased mitochondria).

### (d) Gap / sketch

Fine-grained rescue would require: snapshot PE runtime state, detect
compromise (trust cascade apoptosis) across MANY subjects, shut down current
PE subsystem, relaunch with `/usr/lib/pe-compat-backup/` DLL set, verify
clean, restore. This is MRT analog.

The scaffolding **does** exist via bootc rollback in S72 — but it's
**reboot-granularity**, not runtime. No priority for this session. Flag as
"future work / if we ever have clinically sick PE runtimes that need rescue
without reboot."

### (e) Fidelity: **absent** (but bootc rollback is the coarse-grained equivalent)

---

## Retrograde signaling gap — the structural finding

The task asked specifically: "What does biology do that we don't?"

The 14-mechanism survey produces a clean answer. Biology has **four
independent retrograde-signaling channels** from mitochondrion to nucleus:

| Channel | Latency | Granularity | Shape |
|---|---|---|---|
| **A. mtUPR (ATF5)** | minutes | subsystem-wide | threshold escalation |
| **B. Mitokines (FGF21/GDF15)** | minutes-hours | systemic | secreted broadcast |
| **C. Cytochrome c / cardiolipin** | seconds | per-organelle urgent | point-of-no-return |
| **D. mtROS redox / Ca²⁺ (MAMs)** | milliseconds | continuous metabolic | analog-gradient coupling |

ARCHWINDOWS has the wires for all four but only one channel's **receiver**
is built:

- **A mtUPR**: WIRE missing (no PE-aggregate "I am failing" event). §7 fix.
- **B Mitokines**: WIRE missing (event bus has per-process, not
  per-subsystem). §8 fix. **HIGHEST LEVERAGE.**
- **C Cyt c**: WIRE PRESENT on emit (trust_algedonic.c), WIRE MISSING on
  receive (no cortex reader). §12 fix. **LOWEST LOC WIN.**
- **D mtROS/MAMs**: WIRE present at coarse granularity (coherence_bridge.py
  setpoint mode); fine-grained continuous channel missing. §13 future work.

**The project's event bus architecture is already "the right shape" — the
missing pieces are specific emitters and specific readers, not architectural
redesign.**

---

## What to build in S74 Agent-C follow-up (pull-request scope)

Ordered by leverage per LOC:

1. **algedonic_reader.py** (~130 LOC). Cyt-c wire-up. Unlocks 9 pre-built
   kernel reason codes. Ships a working retrograde-signaling channel today.

2. **PE_EVT_SUBSYSTEM_STRESS** (~125 LOC). Mitokine-equivalent systemic
   signal. Closes the "cortex doesn't see PE subsystem health" gap flagged
   in the task spec.

3. **PE_EVT_EXCEPTION emission in SEH** (~40 LOC). Cyt c release from the
   PE side: a process crashed, tell the cortex. Defined but never emitted
   as noted in the top-3 summary.

4. **pe_upr_observer.py** (~150 LOC). ATF5-equivalent aggregator.
   Subscribes to unimplemented/exception/deny events per-subject with
   exponential decay, fires mtUPR_ACTIVATED escalation.

5. **TRUST_FLAG_DAMAGED** cardiolipin-equivalent pre-apoptotic flag
   (~30 LOC). Recoverable damage marker below apoptosis threshold.

6. **Graduated mitophagy** damage_score in `SubjectProfile` (~40 LOC).
   Convert binary-apoptosis to graduated-tag-then-engulf.

Total ~515 LOC across 6 files, 4 of them new. Would close the retrograde-
signaling gap end-to-end and give the architecture a biology-faithful
organelle-to-cortex communication stack.

---

## Citations (84, numbered)

### Endosymbiosis foundations

1. Sagan, L. (1967). "On the origin of mitosing cells". *J. Theor. Biol.*
   14(3):225-274.
2. Martin, W.F., Mentel, M. (2010). "The origin of mitochondria". *Nature
   Education* 3(9):58.
3. Archibald, J.M. (2015). "Endosymbiosis and eukaryotic cell evolution".
   *Curr. Biol.* 25(19):R911-R921.
4. Imachi, H. et al. (2020). "Isolation of an archaeon at the prokaryote-
   eukaryote interface". *Nature* 577:519-525.
5. Archibald, J.M. (2017). "Lynn Margulis and the endosymbiont hypothesis:
   50 years later". *Mol. Biol. Cell* 28(10):1285-1287.

### mtDNA retention / CoRR hypothesis

6. Adams, K.L., Palmer, J.D. (2003). "Evolution of mitochondrial gene
   content: gene loss and transfer to the nucleus". *Mol. Phylogenet. Evol.*
   29(3):380-395.
7. Allen, J.F. (2003). "The function of genomes in bioenergetic organelles".
   *Phil. Trans. R. Soc. Lond. B* 358(1429):19-38.
8. Timmis, J.N. et al. (2004). "Endosymbiotic gene transfer: organelle
   genomes forge eukaryotic chromosomes". *Nat. Rev. Genet.* 5(2):123-135.
9. Björkholm, P. et al. (2015). "Mitochondrial genomes are retained by
   selective constraints on protein targeting". *PNAS* 112(33):10154-10161.

### TOM/TIM protein import

10. Pfanner, N., Warscheid, B., Wiedemann, N. (2019). "Mitochondrial
    proteins: from biogenesis to functional networks". *Nat. Rev. Mol. Cell
    Biol.* 20(5):267-284.
11. Araiso, Y. et al. (2019). "Structure of the mitochondrial import gate
    reveals distinct preprotein paths". *Nature* 575:395-401.
12. Wang, W. et al. (2020). "Atomic structure of human TOM core complex".
    *Cell Discovery* 6:67.
13. Sim, S.I. et al. (2023). "Structural basis of mitochondrial protein
    import by the TIM23 complex". *Nature* 621:620-626.
14. Rout, S. et al. (2025). "Dynamic TOM–TIM23 supercomplex directs
    mitochondrial protein translocation and sorting". *Nat. Struct. Mol.
    Biol.* 32:411-423.

### MICOS and cristae

15. Hessenberger, M. et al. (2017). "Regulated membrane remodeling by Mic60
    controls formation of mitochondrial crista junctions". *Nat. Commun.*
    8:15258.
16. Stephan, T. et al. (2020). "MICOS assembly controls mitochondrial inner
    membrane remodeling and crista junction redistribution". *EMBO J.*
    39(14):e104105.
17. Mukherjee, I. et al. (2021). "MICOS and the mitochondrial inner
    membrane morphology — when things get out of shape". *FEBS Lett.*
    595(8):1159-1183.
18. Glytsou, C. et al. (2025). "Mitochondrial cristae remodeling: mechanisms,
    functions, and pathology". *Curr. Res. Cell Biol.* 5:100022.
19. Steinegger, M. et al. (2025). "Molecular machineries shaping the
    mitochondrial inner membrane". *Nat. Rev. Mol. Cell Biol.* doi:10.1038/s41580-025-00854-z.

### Drp1/Mfn fission/fusion

20. Otera, H. et al. (2010). "Mff is an essential factor for mitochondrial
    recruitment of Drp1 during mitochondrial fission in mammalian cells".
    *J. Cell Biol.* 191(6):1141-1158.
21. Kalia, R. et al. (2018). "Structural basis of mitochondrial receptor
    binding and constriction by DRP1". *Nature* 558:401-405.
22. Daumke, O., Roux, A. (2023). "Mitochondrial homeostasis maintenance by
    dynamins Mfn1/Mfn2 and Drp1". *Nat. Rev. Mol. Cell Biol.* 24:663-682.
23. Quintana-Cabrera, R., Scorrano, L. (2025). "DRP1, fission and
    apoptosis". *Cell Death Discov.* 11:127.
24. Giacomello, M. et al. (2020). "The cell biology of mitochondrial
    membrane dynamics". *Nat. Rev. Mol. Cell Biol.* 21(4):204-224.

### PINK1/Parkin mitophagy

25. Narendra, D. et al. (2008). "Parkin is recruited selectively to
    impaired mitochondria and promotes their autophagy". *J. Cell Biol.*
    183(5):795-803.
26. Lazarou, M. et al. (2015). "The ubiquitin kinase PINK1 recruits
    autophagy receptors to induce mitophagy". *Nature* 524:309-314.
27. Pickles, S., Vigié, P., Youle, R.J. (2018). "Mitophagy and quality
    control mechanisms in mitochondrial maintenance". *Curr. Biol.*
    28(4):R170-R185.
28. Wang, L. et al. (2020). "Post-translational modifications of key
    machinery in the control of mitophagy". *Trends Biochem. Sci.*
    45(1):58-75.
29. Narendra, D.P., Youle, R.J. (2024). "The role of PINK1-Parkin in
    mitochondrial quality control". *Nat. Cell Biol.* 26:1227-1241.
30. Onishi, M., Yamano, K. (2025). "Molecular mechanisms and physiological
    functions of mitophagy". *Nat. Rev. Mol. Cell Biol.*

### mtUPR

31. Fiorese, C.J. et al. (2016). "The transcription factor ATF5 mediates a
    mammalian mitochondrial UPR". *Curr. Biol.* 26(15):2037-2043.
32. Münch, C., Harper, J.W. (2016). "Mitochondrial unfolded protein
    response controls matrix pre-RNA processing and translation". *Nature*
    534:710-713.
33. Shpilka, T., Haynes, C.M. (2018). "The mitochondrial UPR: mechanisms,
    physiological functions and implications in ageing". *Nat. Rev. Mol.
    Cell Biol.* 19(2):109-120.
34. Lai, C.-H. et al. (2024). "ATF5-mediated mitochondrial unfolded
    protein response protects against Pb-induced mitochondrial damage".
    *Arch. Toxicol.* 98(2):521-535.
35. Anderson, N.S., Haynes, C.M. (2020). "Folding the mitochondrial UPR
    into the integrated stress response". *Trends Cell Biol.* 30(6):428-439.
36. Quirós, P.M. et al. (2017). "Multi-omics analysis identifies ATF4 as a
    key regulator of the mitochondrial stress response in mammals". *J.
    Cell Biol.* 216(7):2027-2045.

### Mitokines

37. Kharitonenkov, A. et al. (2005). "FGF-21 as a novel metabolic
    regulator". *J. Clin. Invest.* 115(6):1627-1635.
38. Kim, K.H. et al. (2013). "Autophagy deficiency leads to protection from
    obesity and insulin resistance by inducing FGF21 as a mitokine". *Nat.
    Med.* 19(1):83-92.
39. Chung, H.K. et al. (2017). "Growth differentiation factor 15 is a
    myomitokine governing systemic energy homeostasis". *J. Cell Biol.*
    216(1):149-165.
40. Ost, M. et al. (2018). "Muscle mitohormesis promotes cellular survival
    via serine biosynthesis". *Cell Metab.* 28(4):622-631.
41. Forsström, S. et al. (2019). "Fibroblast growth factor 21 drives
    dynamics of local and systemic stress responses in mitochondrial
    myopathy". *Cell Metab.* 30(6):1040-1054.
42. Keipert, S., Ost, M. (2021). "Stress-induced FGF21 and GDF15 in
    obesity and obesity resistance". *Trends Endocrinol. Metab.*
    32(11):904-915.
43. Conte, M. et al. (2023). "The dual role of FGF21 in metabolic
    adaptation and mitochondrial stress response". *Front. Endocrinol.*
    14:1264530.
44. Fisher, F.M., Maratos-Flier, E. (2016). "Understanding the physiology
    of FGF21". *Annu. Rev. Physiol.* 78:223-241.

### mtROS redox signaling

45. Murphy, M.P. (2009). "How mitochondria produce reactive oxygen
    species". *Biochem. J.* 417(1):1-13.
46. Holmström, K.M., Finkel, T. (2014). "Cellular mechanisms and
    physiological consequences of redox-dependent signalling". *Nat. Rev.
    Mol. Cell Biol.* 15(6):411-421.
47. Sies, H. (2017). "Hydrogen peroxide as a central redox signaling
    molecule in physiological oxidative stress". *Redox Biol.* 11:613-619.
48. Kasai, S. et al. (2020). "Regulation of Nrf2 by mitochondrial reactive
    oxygen species in physiology and pathology". *Biomolecules* 10(2):320.
49. Chouchani, E.T. et al. (2016). "A unifying mechanism for mitochondrial
    superoxide production during ischemia-reperfusion injury". *Cell Metab.*
    23(2):254-263.
50. Woo, J. et al. (2025). "Pro-inflammatory macrophages produce
    mitochondria-derived superoxide by reverse electron transport at
    complex I that regulates IL-1β release during NLRP3 inflammasome
    activation". *Nat. Metab.* doi:10.1038/s42255-025-01224-x.

### Cardiolipin

51. Gonzalvez, F., Gottlieb, E. (2007). "Cardiolipin: setting the beat of
    apoptosis". *Apoptosis* 12(5):877-885.
52. Kagan, V.E. et al. (2005). "Cytochrome c acts as a cardiolipin
    oxygenase required for release of proapoptotic factors". *Nat. Chem.
    Biol.* 1(4):223-232.
53. Paradies, G. et al. (2014). "Functional role of cardiolipin in
    mitochondrial bioenergetics". *Biochim. Biophys. Acta* 1837(4):408-417.
54. Dudek, J. (2017). "Role of cardiolipin in mitochondrial signaling
    pathways". *Front. Cell Dev. Biol.* 5:90.
55. Pizzuto, M., Pelegrin, P. (2020). "Cardiolipin in immune signaling and
    cell death". *Trends Cell Biol.* 30(11):892-903.
56. Maguire, J.J. et al. (2017). "Known unknowns of cardiolipin signaling:
    The best is yet to come". *Biochim. Biophys. Acta* 1862(1):8-24.
57. Paradies, G. et al. (2019). "Role of cardiolipin in mitochondrial
    function and dynamics in health and disease: molecular and
    pharmacological aspects". *Cells* 8(7):728.

### N-formyl peptides / FPR1

58. Marasco, W.A. et al. (1984). "The identification and isolation of a
    new class of chemotactic factors which are N-formyl peptides". *J.
    Biol. Chem.* 259(9):5430-5439.
59. Rabiet, M.J. et al. (2010). "Mitochondrial N-formyl peptides cause
    airway contraction and lung neutrophil infiltration via formyl peptide
    receptor activation". *J. Biol. Chem.* 285(10):7492-7500.
60. Wenceslau, C.F. et al. (2013). "Mitochondrial-derived N-formyl
    peptides: novel links between trauma, vascular collapse and sepsis".
    *Med. Hypotheses* 81(4):532-535.
61. Kang, J.W. et al. (2020). "FPR1 blockade prevents receptor regulation
    by mitochondrial DAMPs and preserves neutrophil function after
    trauma". *Crit. Care Med.* 48(6):e489-e497.
62. Krychtiuk, K.A. et al. (2021). "Mitochondrial N-formyl methionine
    peptides associate with disease activity as well as contribute to
    neutrophil activation in patients with rheumatoid arthritis". *J.
    Autoimmun.* 120:102629.
63. Dorward, D.A. et al. (2015). "The role of formylated peptides and
    formyl peptide receptor 1 in governing neutrophil function during
    acute inflammation". *Am. J. Pathol.* 185(5):1172-1184.
64. Chen, X. et al. (2023). "Mitochondrial N-formyl methionine peptides
    contribute to exaggerated neutrophil activation in patients with
    COVID-19". *Virulence* 14(1):2218077.

### Cytochrome c release / MOMP

65. Liu, X. et al. (1996). "Induction of apoptotic program in cell-free
    extracts: requirement for dATP and cytochrome c". *Cell* 86(1):147-157.
66. Kluck, R.M. et al. (1997). "The release of cytochrome c from
    mitochondria: a primary site for Bcl-2 regulation of apoptosis".
    *Science* 275(5303):1132-1136.
67. Czabotar, P.E. et al. (2014). "Control of apoptosis by the BCL-2
    protein family: implications for physiology and therapy". *Nat. Rev.
    Mol. Cell Biol.* 15(1):49-63.
68. Bock, F.J., Tait, S.W.G. (2020). "Mitochondria as multifaceted
    regulators of cell death". *Nat. Rev. Mol. Cell Biol.* 21(2):85-100.
69. Li, P. et al. (1997). "Cytochrome c and dATP-dependent formation of
    Apaf-1/caspase-9 complex initiates an apoptotic protease cascade".
    *Cell* 91(4):479-489.
70. Kalkavan, H., Green, D.R. (2018). "MOMP, cell suicide as a BCL-2 family
    business". *Cell Death Differ.* 25(1):46-55.
71. Riley, J.S., Tait, S.W. (2020). "Mitochondria and pathogen immunity:
    from killer to guardian". *Trends Microbiol.* 28(9):793-805.

### MAMs (ER-mitochondria contact sites)

72. Csordás, G. et al. (2006). "Structural and functional features and
    significance of the physical linkage between ER and mitochondria".
    *J. Cell Biol.* 174(7):915-921.
73. Giorgi, C. et al. (2015). "Mitochondria-associated membranes:
    composition, molecular mechanisms, and physiopathological
    implications". *Antioxid. Redox Signal.* 22(12):995-1019.
74. Szabadkai, G. et al. (2006). "Chaperone-mediated coupling of
    endoplasmic reticulum and mitochondrial Ca²⁺ channels". *J. Cell Biol.*
    175(6):901-911.
75. De Stefani, D. et al. (2011). "A forty-kilodalton protein of the
    inner membrane is the mitochondrial calcium uniporter". *Nature*
    476:336-340.
76. Giamogante, F. et al. (2024). "Crosstalk between mitochondria-ER
    contact sites and the ubiquitin-proteasome system". *Trends Cell Biol.*
    34(11):919-932.
77. Prudent, J., McBride, H.M. (2017). "The mitochondria-endoplasmic
    reticulum contact sites: a signalling platform for cell death". *Curr.
    Opin. Cell Biol.* 47:52-63.
78. Liang, D. et al. (2024). "ER-mitochondria distance is a critical
    parameter for efficient mitochondrial Ca²⁺ uptake and oxidative
    metabolism". *Commun. Biol.* 7:1193.

### Mitochondrial donation / MRT

79. Craven, L. et al. (2010). "Pronuclear transfer in human embryos to
    prevent transmission of mitochondrial DNA disease". *Nature* 465:82-85.
80. Tachibana, M. et al. (2013). "Towards germline gene therapy of
    inherited mitochondrial diseases". *Nature* 493:627-631.
81. Hyslop, L.A. et al. (2016). "Towards clinical application of
    pronuclear transfer to prevent mitochondrial DNA disease". *Nature*
    534:383-386.
82. Greenfield, A. et al. (2017). "Assisted reproductive technologies to
    prevent human mitochondrial disease transmission". *Nat. Biotechnol.*
    35(11):1059-1068.
83. McGrath, J.C. et al. (2025). "Mitochondrial donation and
    preimplantation genetic testing for mtDNA disease". *N. Engl. J. Med.*
    392(11):1027-1038.
84. Lyu, Y., Ma, H. (2025). "Recent advances in mitochondrial replacement
    therapy and its future expectations". *Clin. Transl. Discov.*
    5:e70010.

---

## Provenance and cross-project links

- Memory index: `memory/session73_12framework_meta_exploit.md` (framework
  convergence analysis that mapped PE loader onto endosymbiont theory).
- Prior research: `docs/research/s73_g_endosymbiosis.md` (structural mapping,
  CoRR lock audit).
- Trust kernel algedonic primitive: `trust/kernel/trust_algedonic.c` +
  `trust/include/trust_algedonic.h`.
- Trust observer: `ai-control/daemon/trust_observer.py`.
- Event bus: `ai-control/cortex/event_bus.py`.
- Coherence bridge (partial MAM analog): `ai-control/cortex/coherence_bridge.py`.
- Decision engine: `ai-control/cortex/decision_engine.py`.
- PE event emit: `pe-loader/loader/pe_event.c` + `pe-loader/include/eventbus/pe_event.h`.
- SCM crash emit (cyt-c-equivalent already wired on SCM side):
  `services/scm/scm_event.c:143-145` (marks SVC_EVT_CRASH + SVC_EVT_DEPENDENCY_FAIL as URGENT).

End of S74-C deliverable.
