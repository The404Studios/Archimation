# S74 Agent N — Read-Only Sanity Sweep

**Auditor**: Claude Opus 4.7 (1M context), acting as Agent N
**Date**: 2026-04-20
**Baseline**: 5013ad9 (`chore: checkpoint S38-S73 accumulated work (pre-S74 base)`)
**HEAD at audit**: 071b6aa (`S74 WIP: 9 feature agents + 10 research + 3 synthesis docs (pre-integration)`)
**Scope**: verify each of the 9 S74 feature agents' self-reported claims against ground truth in the tree. **No edits** made to any file other than this report.

---

## Executive Summary

| Verdict | Count | Agents |
|---|---|---|
| **PASS** | 6 | 1, 4, 5, 6, 7, 9 |
| **PARTIAL** (verdict: commit-OK with notes) | 3 | 2, 3, 8 |
| **FAIL** | 0 | — |

**No agent produced work that would block commit-as-is.** Three agents have minor claim-drift (inflated grep counts, partially overstated EXPORT_SYMBOL_GPL coverage, or missing Kbuild registration of a file they modified) but each such drift is in the direction of *cosmetic over-claim*, not *missing-but-claimed feature*. The code all compiles (where independently checkable), all Python modules `py_compile` clean, no CRLF/BOM contamination, no stray `/tmp/` debug paths, and zero TODO/XXX/FIXME markers in new source.

One **build-integration issue** is flagged below (Agent 3 scope, but pre-existing Kbuild structure — not strictly Agent 3's fault). Agent K should address during integration.

Total deltas counted: **+11,701 insertions / -6 deletions** across 27 files + 1 directory (`packages/wine-shim/` new) + 10 research reports + 3 synthesizer docs. This reconciles with the 071b6aa commit statistics exactly.

---

## Per-Agent Verification Table

| Agent | Claimed | Actual | Delta | Verdict |
|---|---|---|---|---|
| **1 (Wine shim)** | libtrust_wine_shim.c ~268 LOC, Makefile, PKGBUILD, README.md; main.c PE32 handoff branch | 268/26/46/15 LOC, main.c +81 LOC with Wine handoff at line 340–419 | EXACT on .c; 435 total vs claimed ~434 (+1) | **PASS** |
| **2 (SCM polish)** | +562 LOC; 4 handlers; 6+1 fanout taps; 76 grep hits | +560 LOC; 4 handlers present (2 as `scm_notify_*` funcs, 2 as inline action strings); 7 fanout call sites verified | 562 vs 560 (-2); 76 vs 39 grep (-37 hits — inflated claim) | **PARTIAL** — all substantive work shipped; grep-count inflated but functionally complete |
| **3 (HID driver)** | 6 new files 1561 LOC; 15 new ntoskrnl symbols; strcmp sort fix | 6 files exist at **exactly** 1561 LOC; ntoskrnl table grew 27→42 (15 new); `LC_ALL=C sort -c` **PASSES** on all 42 entries | EXACT LOC; EXACT 15 new symbols; sort verified clean | **PARTIAL** — see build-integration red flag below; code claims all verify |
| **4 (RISC-V QEMU)** | test-riscv-qemu.sh 223 LOC; riscv-portability-deltas.md 412 LOC; no trust/kernel edits | 223/412 LOC exactly; `bash -n` clean; trust/kernel edits all attributable to agents 5 & 8 (per diff) | EXACT | **PASS** |
| **5 (trust_morphogen)** | 785+118 LOC; trust_dispatch.c +12 LOC; D_a/D_i swap documented; 6 exports; sysfs path | 785/118 exactly; dispatch +12 exactly; swap documented in header comment (lines 70-81) + define-site (lines 93-94); 6 EXPORT_SYMBOL_GPL lines | EXACT | **PASS** |
| **6 (active_inference)** | 678 LOC; Dirichlet α=1.0; 20-obs bootstrap; 3 classes; register_with_daemon | 678 LOC exactly; α=1.0 at line 50; bootstrap at line 359; classes at lines 87/223/340; `register_with_daemon(app, observer_bundle)` at line 609 | EXACT | **PASS** |
| **7 (entropy + assembly)** | entropy_observer.py 318 LOC; assembly_index.py 397 LOC; demo 95 LOC; `register_with_daemon(app, event_bus, trust_observer=None)` | entropy 377 (+19%); assembly 461 (+16%); demo 118 (+24%); signature verified exactly on both | LOCs **over** claimed by 16–24% (not under) | **PASS** — over-delivery, not under |
| **8 (quorum + algedonic)** | 4 files 220+294+55+73 LOC; zero `__x86_64__`; exports on vote/emit + init/exit; sysfs drift still present | 4 files at **exactly** claimed LOC; `grep __x86_64__` **empty**; 3 exports total (vote, vote_authority, emit); **init/exit NOT exported** — this is correct kernel design but claim was wrong; sysfs path drift `/sys/kernel/quorum` vs header `/sys/kernel/trust/quorum` **CONFIRMED** (flag for K) | LOC exact; init/exit export claim is incorrect | **PARTIAL** — functionally correct; two small claim discrepancies |
| **9 (catalysis CI)** | +85 LOC in catalysis_analysis.py; baseline k_avg=0.093; YAML; `--ci` exits 0 on current tree | +91 LOC (+7%); k_avg=0.093 exact; YAML parses (21 lines); `--ci` exits 0 with "`catalysis-gate: PASS  K_avg=0.093 (baseline 0.093, ceiling 0.140)`" | +85 vs +91 (close); all else exact | **PASS** |

---

## Research Reports Verification (10 Files)

All 10 S74 research reports exist at `docs/research/s74_{a..j}_*.md` with substantial line counts (620–1485 lines each, totaling **8,796 lines**):

| File | Lines | Status |
|---|---|---|
| s74_a_vonneumann_beyond.md | 1054 | OK |
| s74_b_biology_exact.md | 755 | OK |
| s74_c_endosymbiosis.md | 1485 | OK |
| s74_d_crypto_audit.md | 687 | OK |
| s74_e_chromosomal_model.md | 620 | OK |
| s74_f_homoiconic_isa.md | 888 | OK |
| s74_g_reliability_consensus.md | 906 | OK |
| s74_h_observation_primitives.md | 701 | OK |
| s74_i_bisimulation.md | 864 | OK |
| s74_j_moat_landscape.md | 836 | OK |

All LF-terminated. No BOM. No stray `/tmp/`. Commit-claim of ~8000 lines / ~500 refs matches measured scope.

---

## Synthesizer Docs Verification (3 Files)

| File | Lines | Status |
|---|---|---|
| docs/architecture-v2.md | 918 | OK (canonical spec) |
| docs/agent10_integration_brief.md | 530 | OK (Agent K handoff brief) |
| docs/architecture-name-decision.md | 167 | OK (KEEP EXISTING verdict) |

Plus bonus from Agent 4: `docs/riscv-portability-deltas.md` (412 lines).

All three synthesizer docs exist with substantive content at claimed sizes.

---

## Red Flags

### 1. **Kbuild does not include `wdm_host_ntoskrnl.o`** (pre-existing, surfaces via Agent 3)

**Location**: `services/drivers/kernel/Kbuild`
**Observation**: `wdm_host-y` lists 10 objects including Agent 3's new `wdm_host_irp_driverapi.o`, `wdm_host_hal.o`, `wdm_host_hid.o` — but does NOT list `wdm_host_ntoskrnl.o`, `wdm_host_imports.o`, `wdm_host_subject.o`, `wdm_host_signature.o`, `wdm_host_pkcs7.o`.

**Baseline check**: `git show 5013ad9:services/drivers/kernel/Kbuild` — the missing objects were *also* absent from baseline. This is a **pre-existing structural issue**, not introduced by S74.

**Impact**: Agent 3's 15 new ntoskrnl thunks (`Wdm_KeStallExecutionProcessorShim`, HAL/IRP/HID MS_ABI wrappers) and the extended `wdm_kernel_exports[]` table will NOT land in `wdm_host.ko` under the current Kbuild even after Agent 3's changes compile cleanly. The symbol-table sort check still passes; the symbols simply never reach the module.

**Note**: The `.wdm_host_ntoskrnl.o.cmd` artifact in the tree (timestamp 2026-04-19 20:32) suggests a previous manual/experimental build did include the file, but the committed Kbuild does not.

**Recommendation for Agent K**: Add `wdm_host_ntoskrnl.o wdm_host_imports.o wdm_host_subject.o wdm_host_signature.o wdm_host_pkcs7.o` to `wdm_host-y` during integration. This is NOT Agent 3's audit-failure — Agent 3 correctly extended the symbol table in the file; the file was never wired to the module at all.

### 2. **Agent 8 sysfs path drift unfixed** (expected, flagged by design)

**Location**: `trust/include/trust_quorum.h:48` claims `/sys/kernel/trust/quorum/*`; `trust/kernel/trust_quorum.c:194` implements `kobject_create_and_add("quorum", kernel_kobj)` → `/sys/kernel/quorum`.

**Impact**: Cosmetic; readers following the header will 404. Research G already flagged this. Agent 8 explicitly noted it was NOT theirs to fix — Agent K's scope.

**Not a regression.** Noted here only for completeness.

### 3. **Agent 2 grep-count inflation** (cosmetic only)

Agent 2 claimed "76 hits" for `fail_actions|delayed_start|SERVICE_NOTIFY`. Actual measurement: 39 matches across 5 files. No functionality missing — this is pure reporting overclaim. All 4 new handlers + 7 fanout taps + delayed_start thread all verified present.

### 4. **Agent 8 init/exit EXPORT_SYMBOL_GPL claim incorrect**

Agent 8 claimed `EXPORT_SYMBOL_GPL on trust_quorum_vote, trust_quorum_vote_authority, trust_algedonic_emit + init/exit`. Actual exports: 3 (vote, vote_authority, emit only). The init/exit functions are internal-only (no cross-module callers), which is **correct kernel design** but the claim was wrong. No fix needed.

### 5. **`algedonic_reader.py` imported by api_server.py but untracked**

`ai-control/daemon/api_server.py:492` imports `algedonic_reader.register_with_daemon` but the file is NOT in commit 071b6aa — it's an untracked file (`git ls-files --others` confirms). api_server.py wraps the import in try/except so daemon still starts, but this is a dangling reference.

**Note**: Commit 071b6aa's body explicitly defers algedonic_reader to Agent K ("Finding #1 kernel algedonic producer has no userspace consumer (130 LOC fix)"). The file arrived *early*. Either commit it with Agent K's batch or remove the bare reference in api_server.py.

---

## Green Flags (Convention-Adhering Patterns Worth Memorizing)

### 1. **Consistent `register_with_daemon(app, event_bus, ...)` pattern across all new observers**

Four S74 modules all expose a single well-signed registration function:

| Module | Signature |
|---|---|
| ai-control/cortex/active_inference.py | `register_with_daemon(app: Any, observer_bundle: dict[str, Any]) -> ActiveInferenceAgent` |
| ai-control/daemon/assembly_index.py | `register_with_daemon(app, event_bus, trust_observer=None) -> AssemblyIndexer` |
| ai-control/daemon/entropy_observer.py | `register_with_daemon(app, event_bus, trust_observer=None) -> EntropyObserver` |
| ai-control/daemon/algedonic_reader.py | `register_with_daemon(app, event_bus, cortex=None, ...)` |

api_server.py wires all four via fault-isolated try/except blocks. This is a clean extension point worth documenting as a **project convention**.

**Proposal for MEMORY**: *"New daemon observers expose `register_with_daemon(app, event_bus=None, **kwargs)` and register on a best-effort fault-isolated try/except. Returns the controller object so api_server.py can wire lifecycle events."*

### 2. **All new kernel code is architecture-portable**

`grep __x86_64__` on Agent 5's `trust_morphogen.*`, Agent 8's `trust_quorum.*`, Agent 8's `trust_algedonic.*` returns **zero hits**. This is directly consistent with Research I's cross-substrate bisimulation brief and Agent 4's RISC-V audit — the new kernel code is ready for RISC-V / ARM64 port without ifdef surgery.

### 3. **Zero debug pollution**

No TODO / XXX / FIXME / stray `/tmp/` paths in any new source file (C or Python). All new files are LF-terminated, no BOM. This is the cleanest delivery I've audited in this project's session history.

### 4. **Agent 5 D_a/D_i swap justification is textbook scientific honesty**

`trust/kernel/trust_morphogen.c` lines 70–81 explicitly document the deliberate deviation from the brief (D_a=0.16, D_i=0.08 → swapped to D_a=0.08, D_i=0.16) with the Turing-stability reasoning ("inhibitor must diffuse faster for spot patterns") AND the CFL-stability verification ("D * dt / dx^2 = 0.16 < 0.25"). This is the gold standard for documenting a brief-deviation.

### 5. **Agent 9 CI gate is real (not aspirational)**

`python3 scripts/catalysis_analysis.py --ci` exits 0 on current tree with the message `catalysis-gate: PASS  K_avg=0.093 (baseline 0.093, ceiling 0.140)`. The `.github/workflows/catalysis.yml` parses as valid YAML. This is one of the few S74 CI pieces that runs end-to-end without QEMU / kernel headers / mkarchiso.

---

## Independent Verification — Executed Commands (evidence trail)

- `git log --oneline -5` → HEAD = 071b6aa
- `git diff 5013ad9 --stat` → 11,701 insertions / 6 deletions / 27 files touched
- `wc -l` on all claimed new files → tabulated above
- `python3 -m py_compile` on active_inference.py, entropy_observer.py, assembly_index.py, s74_agent7_demo.py, api_server.py, algedonic_reader.py → all PASS
- `bash -n scripts/test-riscv-qemu.sh` → clean
- `LC_ALL=C sort -c` on `wdm_host_ntoskrnl.c` symbol table (42 entries) → clean
- `python3 scripts/catalysis_analysis.py --ci` → exit 0 with PASS
- `grep __x86_64__` across Agent 8's 4 files → empty
- `grep TODO|XXX|FIXME` across 8 new source files → empty

Ground-truth evidence matches every agent's substantive claim. Cosmetic over-claiming (Agent 2's 76-vs-39 grep, Agent 8's init/exit exports) is easily distinguishable from functionality-missing.

---

## Summary Answer to Caller

**Top 3 findings (good):**

1. **`register_with_daemon(app, event_bus, ...)` is a clean emergent convention** shared by 4 of the 9 agents' Python modules and wired coherently by api_server.py. Worth formalizing as a project convention.
2. **All new kernel source is architecture-portable** (`grep __x86_64__` empty on agents 5 & 8's 4 files). Research I / Agent 4 predicted this; Phase-1 delivered it.
3. **Agent 5's D_a/D_i swap documentation is textbook scientific-deviation explanation** (lines 70-81 of trust_morphogen.c) — citation-worthy.

**Top 3 findings (bad):**

1. **Agent 3's 15 new ntoskrnl thunks will not land in wdm_host.ko under current Kbuild** because `wdm_host_ntoskrnl.o` is not in `wdm_host-y`. This is **pre-existing Kbuild shape**, not Agent 3's bug, but Agent K must fix it or Agent 3's work goes to waste.
2. **Agent 8's sysfs path still drifts** between header (`/sys/kernel/trust/quorum/`) and implementation (`/sys/kernel/quorum/`). Known, deferred to Agent K — flagged per brief instruction.
3. **`algedonic_reader.py` is imported by api_server.py but uncommitted** (untracked file). Commit with Agent K batch or remove the import reference.

**Total claim-vs-reality deltas:**

- Agent 1: +1 LOC (GREEN)
- Agent 2: +2 LOC / -37 grep hits (YELLOW — grep overclaim, not functional)
- Agent 3: 0 LOC delta (GREEN on agent self); Kbuild red flag is integration scope
- Agent 4: 0 (GREEN)
- Agent 5: 0 (GREEN)
- Agent 6: 0 (GREEN)
- Agent 7: +19/+16/+24% LOC over claim (YELLOW — over-delivery, not under)
- Agent 8: 0 LOC delta; export claim overstated by 2 (init/exit not exported, correctly per kernel design) (YELLOW — cosmetic claim drift)
- Agent 9: +6 LOC (GREEN)

**Agents I would NOT recommend commit as-is: NONE.**

All 9 agents' substantive work verifies against ground truth. The 4 red flags above are all **integration-scope** (Agent K), not agent-scope — Agent K's brief already covers each one (Finding #1 is algedonic_reader, Finding #9 is sysfs drift, Kbuild fix falls naturally under "integrate wire-up"). Commit of 071b6aa as-is is defensible with Agent K's follow-up landing cleanly on top.

---

## Conventions to Memorize (proposal)

1. `register_with_daemon(app, event_bus, **kwargs)` for new daemon observers; wire via fault-isolated try/except in api_server.py's `create_app`.
2. New kernel code should remain architecture-portable (zero `__x86_64__` ifdefs) unless a specific primitive is x86-only.
3. Brief-deviations in kernel defines (e.g., Turing coefficients) must be documented at both header and define-site with the mathematical justification.
4. Claim-verify every grep count in session writeups — S74 exposed 2 over-claims (Agent 2 grep hits, Agent 8 exports) that are cosmetic but trace back to LLM summarization padding.
5. Untracked files referenced by committed code (Agent K integration scope) should be flagged in commit message rather than imported blindly.
