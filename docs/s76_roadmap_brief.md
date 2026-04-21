# ARCHIMATION — S76 Roadmap Brief

**Document status:** working brief, not a sprint plan. Lighter than
`docs/s75_roadmap.md` (992 LOC) because the user has stated the roadmap
should be *spontaneous as we move through the project* — this brief
captures what's true now and likely next, without over-committing.
**Author:** S76 Agent A (research + synthesis, read-only).
**Base commit:** `2d5a8ac` — S75 follow-up (three deferred wires landed).
**Prior base:** `a7e2f8d` — S75 8-agent punch-list.
**Date:** 2026-04-21.
**Paper of record:** Roberts / Eli / Leelee, *Root of Authority*,
Zenodo DOI [10.5281/zenodo.18710335](https://doi.org/10.5281/zenodo.18710335).
**User strategic preference:** see
[`memory/feedback_user_favors_coherence_over_velocity.md`](../memory/feedback_user_favors_coherence_over_velocity.md).
The discriminator is whether the architectural claim requires the bigger
move — if yes, surface it; if no, the cheap move is fine. This brief
follows that rule.

---

## §0. State of project after S75

### §0.1 Git HEAD and scope

- `a7e2f8d` — S75 8-agent punch-list. T1-T7 adversarial harness,
  library-census observer, Monte Carlo cortex, bisim scaffolding,
  self-attestation quine, REG_ARG RISC-V port, CFT-honest verdict rename,
  cross-cutting audit. ~3700 LOC across 24 files. All host-runnable
  tests green.
- `2d5a8ac` — S75 follow-up wires (three deferrals consolidated from
  the S75 session boundary memo). Closed BeliefState × library_census,
  quorum HMAC call site, PE_EVT_TRUST_ESCALATE consumer. ~180 LOC
  across 7 files.

### §0.2 Tier audit — deltas from S75

Pre-S75 baseline (per `docs/s75_roadmap.md` §0.2):
**Apps 82-85% / Services 78-80% / Drivers 32-42% / Authority 95% /
Cortex 78-82% / Cross-substrate 5-8%**.

Post-S75 (post-`2d5a8ac`):

| Tier | Pre-S75 | Post-S75 | Delta source |
|------|---------|----------|--------------|
| **Apps (Tier 1)** | 82-85% | 82-85% | No Tier-1 app work this session; structural moat work only. Corpus still 16/18 (not re-run). |
| **Services (Tier 2)** | 78-80% | 78-80% | No service-layer changes. scm_svchost.c dead-code still parked. |
| **Drivers (Tier 3)** | 32-42% | 32-42% | No driver work. |
| **Authority** | 95% | **~97%** | Self-attestation quine folded into APE proof input (`trust_ape.c`, 23-line edit); HMAC on quorum verdicts (`trust_quorum.c` post-S75 follow-up); REG_ARG portability layer on syscall path. Moat widened. T1-T7 harness landed but 12/14 tests await live trust.ko — see §5. |
| **Cortex** | 78-82% | **~85%** | Monte Carlo fully wired with 4 samplers + endpoint; library-census observer live + BeliefState extension (follow-up); PE_EVT_TRUST_ESCALATE consumer registered. Active-inference now reads ecosystem census. |
| **Cross-substrate** | 5-8% | ~10% | REG_ARG{0..5} macros ported trust_syscall.c + trust_memory.c call sites (22 sites); still needs full riscv64 build + QEMU smoke. Bisim APE pure-function cross-check 11/11 byte-exact. |
| **Distro polish** | 60% | 60% | Unchanged. |

**Aggregate:** ~**75-77%** of the way to the product story stated in
`memory/roa_paper_validation_tier_audit_and_s74_plan.md` §7. The moat
gained ~2 percentage points; cortex gained ~3. Tier 1/2/3 stayed
constant because S75 was architectural hardening, not tier delivery —
consistent with S74's pattern.

### §0.3 What moved (cite file:line)

- `trust/kernel/trust_ape.c:22` — 23-line surgical edit adding
  `trust_attest_quine_text_hash()` result to APE proof input.
- `trust/kernel/trust_attest_quine.c:374` — full self-attestation quine
  (S75 Agent E).
- `trust/kernel/trust_quorum.c:157` — CFT-honest verdict rename
  (CONSISTENT/DISCREPANT/DIVERGENT) + HMAC attachment at vote site
  (S75 follow-up).
- `trust/kernel/trust_quorum_hmac.c:112` — quorum L1 HMAC API.
- `trust/include/trust_pt_regs_compat.h:118` — REG_ARG{0..5} macros.
- `trust/kernel/trust_syscall.c` + `trust_memory.c` — 22 call-site
  migration to REG_ARG.
- `ai-control/daemon/library_census.py:454` — Maturana-Varela
  Criterion-1 ecosystem observer.
- `ai-control/cortex/monte_carlo.py:531` — 4 sampler classes, full wire.
- `ai-control/cortex/active_inference.py` — BeliefState extended with
  `library_distribution` field (S75 follow-up).
- `ai-control/cortex/main.py` — `handle_pe_trust_escalate` registered
  (S75 follow-up).
- `tests/adversarial/theorem_violation_suite.py:728` — T1-T7 harness
  (14 methods, 7 classes).
- `tests/bisim/ape_pure_cross.py:308` + `tests/bisim/trace_harness.py:389`
  — empirical bisim scaffolding.

### §0.4 Test state

Host-runnable (from S75 commit messages + `scripts/lint_producer_consumer.py`
run at S76-open):

- `tests/unit/test_monte_carlo.py` — 33/33 PASS
- `tests/unit/test_library_census.py` — 23/23 PASS
- `tests/unit/test_algedonic_reader.py` — 12/12 PASS
- `tests/bisim/test_bisim_smoke.py` — 15/15 PASS; APE pure cross 11/11
  byte-exact
- `tests/adversarial/theorem_violation_suite.py` — 2 PASS, **12 skipped
  pending live trust.ko** (see §5)
- `scripts/lint_producer_consumer.py --ci` — PASS (known=45,
  current_nonok=44)

All bash scripts parse clean; all modified Python files compile.

### §0.5 Producer-consumer lint — current state

From live lint run at S76-open (`scripts/lint_producer_consumer.py`):

- **59 producers scanned**: 11 ok / 21 no-emit / 11 no-consumer / 16
  orphaned.
- **44 non-ok producers are in the known-baseline JSON** (= tracked tech
  debt, not regression).
- **1 current_nonok over baseline** — acceptable drift.

The `[ORPHANED]` class (16 producers, both sides zero) is mostly dormant
event types in `pe-loader/include/eventbus/pe_event.h` and
`services/scm/scm_event.h`. These are **declared-only** channels awaiting
future trust-cortex wire. The baseline guards against new orphans;
existing ones are a documented debt queue.

---

## §1. Open structural items, by tier

### Tier 1 — honest moat closure

#### Item 1 — Live QEMU smoke of T1-T7 adversarial harness (~0 LOC, 1 session)

**Why:** S75 Agent A shipped 14 test methods; 12 of them are
`pytest.skip(...)` gated on trust.ko being loadable and
`tests/adversarial/helpers` binary present (see
`tests/adversarial/theorem_violation_suite.py:88-90`). Until we boot the
ISO under QEMU and run the suite with `/sys/kernel/trust_invariants/`
present, the theorem counters remain observed-at-zero — exactly the gap
the harness was built to close. **Credibility-critical.**

**Acceptance test:** rebuild ISO, boot QEMU, SSH in, `cd
tests/adversarial && make && pytest theorem_violation_suite.py` — 14/14
(or documented skip reasons with a counter-increment log per theorem).
Counter values captured into `docs/runtime-theorem-validation.md`
(currently does not exist; spec living in
`memory/roa_paper_validation_tier_audit_and_s74_plan.md` §6).

**Honest LOC:** 0 net source code. Script + QEMU orchestration may be
~40 LOC glue in `scripts/test-adversarial-qemu.sh`.

#### Item 2 — APE regression resolution (~40 or ~500 LOC, 1 session)

**Why:** `trust/kernel/trust_ape.h:44-52` still claims 720 × 256 × 16 ×
32 = 94,371,840 hash configs; shipping code at `trust_ape.c:40-45`
implements **three**. S74 `faf6d8e` recovered 605 LOC from dangling
commit `9b04ca1`; S75 did not touch this. `docs/ape-regression-archaeology.md`
and `docs/ape-regression-triage.md` contain the forensics. Peer reviewer
of the Zenodo paper flags this on first pass.

**Acceptance test:** either (a) code implements 94M configs with
bit-diffusion benchmark over 10K random inputs (~500 LOC path), or (b)
`trust_ape.h` + `docs/roa-conformance.md` amended to 3-algorithm reality
with paper-disclaimer sentence (~40 LOC path). Either way, internal
inconsistency gone.

**Honest LOC:** 40 (amend) or 400-600 (bring-back full). Decision
deferred — see §4.2.

#### Item 3 — scm_svchost.c resolution (~50 or ~300 LOC, 1 session)

**Why:** S75 Agent H flagged: `services/scm/scm_svchost.c` has no
callers and is not in `services/Makefile`. Either wire to `scm_daemon.c`
(service lifecycle → svchost SHARE_PROCESS grouping proper) or move to
`research/` as a reference design. Pre-S74 issue; surfaced by audit; not
addressed yet.

**Acceptance test:** either (a) `git grep scm_svchost` shows call from
`scm_daemon.c` and binary links clean (~300 LOC), or (b) file moved to
`research/` with README note and removed from service binary (~50 LOC).

**Honest LOC:** 50 (move) or 300 (wire). Leans toward (a) because the
SHARE_PROCESS grouping is described as "landed" in S65 memory — current
state is a producer without a consumer at the code-flow level.

### Tier 2 — cortex / observability

#### Item 4 — Live QEMU smoke of bisim harness (~0 LOC, 1 session, couples with Item 1)

**Why:** `tests/bisim/test_bisim_smoke.py` passes 15/15 on host, but the
full bisim round-trip requires kernel-side trace tap (`tests/bisim/
test_pt_regs_compat.c`) to run on live riscv64-or-x86_64 kernel. Couple
with Item 1 for a single QEMU bring-up session.

**Acceptance test:** trace harness records ≥1 end-to-end round trip
with MockOracle; discrepancy detector correctly flags a fabricated
mismatch (positive control).

**Honest LOC:** 0 source; ~20 LOC script addition.

#### Item 5 — Differential observer (Bateson filter) (~150 LOC, 1 session)

**Why:** `architecture-v2.md` §5 Layer 4 gap list; `docs/research/
s74_h_observation_primitives.md` §1.4. Current observers publish
absolute values; deltas are lost. A ransomware-vs-video-encoder
discriminator that reads first-derivative of entropy + library-density
vs. absolute bytes moved. Library-census (S75 Agent B) is the obvious
first input.

**Acceptance test:** `ai-control/daemon/differential_observer.py`
subscribes to library_census + entropy observers; emits
`ObservationDelta` events; pytest test confirms 3 synthetic workloads
produce distinguishable delta signatures.

**Honest LOC:** 150.

#### Item 6 — Bennett logical-depth observer (~110 LOC, 1 session)

**Why:** `architecture-v2.md` §5 Layer 0 gap list; research H §1.6. The
"deep-computed vs shallow-random" discriminator. Incremental cortex
signal depth; pairs with Item 5.

**Acceptance test:** computes compression-ratio-over-time proxy for
Bennett depth; emits to event bus. Low priority vs. Items 1-3 but cheap.

**Honest LOC:** 110.

### Tier 3 — large moves, multi-session

#### Item 7 — libtrust_wine_shim full integration (~1200 LOC, 2-3 sessions)

**Why:** biggest deferred item from S75 (and from s75_roadmap.md §1.3
Item 10). S74 Agent 1 scaffolded the PE32 handoff shim; the moat-widening
move is to gate Wine's NT syscall layer with APE/TRC/chromosome
semantics via LD_PRELOAD. Turns Wine from "foreign obligate symbiont"
to "trust-kernel-gated symbiont."

**Acceptance test:** LD_PRELOAD `libtrust_wine_shim.so` intercepts
NtCreateFile + NtOpenFile + NtDeviceIoControlFile + NtLoadDriver;
minimum Wine-prefix unit test passes with trust-gate active; 3+ real
PE32 binaries complete full launch → gate → exit lifecycle.

**Honest LOC:** 1200 C shim + ~200 LOC Wine-prefix unit test per
research-J §5 Proposal B. **This is the Tier-3 item flagged by
`feedback_user_favors_coherence_over_velocity.md` as potentially deeper
than it appears** — the moat story for Windows-compat depends on it.

#### Item 8 — Full riscv64 build + QEMU boot (~240 LOC + toolchain, 1-2 sessions)

**Why:** REG_ARG port (S75 Agent F) was the API layer. Actual riscv64
build + QEMU smoke boot is the validation. Blocks bisim harness full
closure.

**Acceptance test:** `make ARCH=riscv64 CROSS_COMPILE=riscv64-linux-gnu-`
builds trust.ko clean; boots in QEMU virt; smoke test confirms
`/sys/kernel/trust_invariants/` present and theorem_1_violations
readable.

**Honest LOC:** 240 + toolchain shell LOC for cross-compile env.

#### Item 9 — Typestate cortex-veto enforcement (~80 LOC, 1 session)

**Why:** I-C1 from `architecture-v2.md` is convention-only. Research J §3.3
flagged as "not mechanically enforced." Python typestate +
`/dev/trust_cortex` restricted device file = 80 LOC of hardening that
closes a real attack surface.

**Acceptance test:** cortex Python refuses to call `trust_action`
through typestate assertion; separate `/dev/trust_cortex` device exposes
only veto ops; malicious-cortex test fails at import time.

**Honest LOC:** 80.

---

## §2. Three small wires already done in S75 follow-up (DO NOT RE-LITIGATE)

Commit `2d5a8ac` landed three cross-agent-boundary items from the S75
session memo. Future Claude: these are DONE. Do not propose them.

1. **BeliefState × library_census wire** —
   `ai-control/cortex/active_inference.py:41-95` adds
   `library_distribution` field to `BeliefState` with
   none/low/mid/high/saturated bucketing of `unique_library_ratio`.
   `ai-control/daemon/api_server.py:31` reorders lifespan registration
   so library_census starts BEFORE active_inference. Cortex now reads
   ecosystem census on every BeliefState snapshot. Default behaviour
   preserved when library_census is absent.

2. **trust_quorum_vote() HMAC call site** —
   `trust/kernel/trust_quorum.c:71` packs {subject_id, field_id,
   verdict, agree} as 16-byte payload after verdict assignment; computes
   HMAC-SHA256 via `trust_quorum_hmac_compute` (Agent E API); exposes
   `/sys/kernel/trust/quorum/last_hmac`, `hmac_computed`, `hmac_failed`.
   Bit-flip adversary that forges sysfs counter rollback cannot also
   forge matching HMAC.

3. **PE_EVT_TRUST_ESCALATE consumer** —
   `ai-control/cortex/event_bus.py:19` parses payload;
   `ai-control/cortex/main.py:38` adds `handle_pe_trust_escalate` with
   decision-engine-first / autonomy fallback semantics; `register_handlers`
   wires `bus.on`. Lint downgrades from ORPHANED (severity=high) to
   NO-EMIT (severity=medium, emits=0, consumers=2). Emit-side wires in
   S76+ when trust-escalate path lands; consumer-first means future emit
   lands on a real handler instead of black-holing.

---

## §3. What S76 should land (Tier-1, recommended)

Don't pad. Per user preference, surface only defensible items. **Three
recommended picks:**

1. **Item 1 — Live QEMU smoke of T1-T7** (0 LOC source, ~40 LOC script).
   Highest coherence payoff: closes the "structural but not runtime
   validated" gap `paper-vs-implementation.md` §0 flags as the biggest
   credibility risk. This is the move the adversarial harness was
   written for; leaving it unrun is producer-without-consumer at the
   session-boundary level.

2. **Item 2 — APE regression resolution** (40 or 500 LOC).
   Peer-reviewer blocker. Either path closes the internal
   inconsistency. Synthesizer recommendation: path (a) amend docs +
   header + paper disclaimer, since research-D §3.1 identifies
   behavioral-state binding (S_n = chromosome_checksum) — not 94M hash
   multiplicity — as APE's genuine novelty. Moat survives the honest
   downgrade.

3. **Item 3 — scm_svchost.c** (50 or 300 LOC). Honest
   producer-without-consumer at the code-flow level; either wire it or
   park it in `research/`. The dead-code state misrepresents the S65
   shipping claim.

**Rationale against piling more items in S76:** S75 landed ~3700 LOC
across 8 agents + 180 LOC in follow-up. That is substantial. S76 as a
**validation + honesty pass** — run the tests that were built, close
the inconsistencies that are known — is higher product-coherence value
than another parallel-agent sprint. Match the cadence of S73 (research) →
S74 (feature) → S75 (hardening) → **S76 (validation)**.

### Optional extensions if bandwidth permits

- **Item 5** (differential observer, 150 LOC) — quick cortex signal
  depth win on top of library-census.
- **Item 9** (typestate cortex-veto, 80 LOC) — cheap and closes a real
  attack surface flagged in architecture-v2.md.

### Do NOT attempt in S76

- Item 7 (libtrust_wine_shim, 1200 LOC) — needs dedicated multi-session
  arc, not a bolt-on.
- Item 8 (full riscv64 build, 240 LOC + toolchain) — toolchain risk;
  stretch if QEMU bring-up for Item 1 goes smoothly.
- Any new speculative research (no "12 framework" re-run per
  s75_roadmap §4.3).

---

## §4. Strategic decisions still open

Carried forward from `docs/s75_roadmap.md` §3 plus new ones from S75
close.

### §4.1 Meiosis rename OR disclaimer (from s75 Decision 1)

**Status after S75:** `docs/paper-vs-implementation.md` §2.T-meiosis
shipped the disclaimer path (paper-text-only). The code-rename path
(`trust_meiosis()` → `trust_dual_authority_bond()`, ~200 LOC mechanical)
is **still open** — see `docs/meiosis-rename-decision.md` (S74
deliverable). User has not chosen.

**Synthesizer recommendation:** defer to S77+. The disclaimer closes the
peer-review attack surface at zero code cost; the rename is polish.

### §4.2 APE regression — bring-back (94M) or amend docs (from s75 Decision 2)

**Status:** triage and archaeology reports exist
(`docs/ape-regression-triage.md`, `docs/ape-regression-archaeology.md`).
S74 `faf6d8e` recovered 605 LOC from dangling commit. No decision
committed yet.

**Synthesizer recommendation:** path (b) amend. See §3 Item 2 rationale.

### §4.3 Paper submission target venue (from s75 Decision 5)

**Status:** open. `docs/paper-vs-implementation.md` §4 recommends
EuroSys or USENIX Security; S75 did not commit.

**Synthesizer recommendation:** EuroSys if submission is H2 2026 (Item 1
live QEMU smoke closes the "runtime validation" gap by then); USENIX
Security if H1 2027 and Item 7 (wine-shim) is in the paper.

### §4.4 NEW — S76 cadence: validation pass or new features?

**The choice:**
- (a) Validation pass (Items 1-3) — 1 session, ~100 LOC + QEMU orchestration.
- (b) New feature push (Items 5/6/9 + parallel agents) — 1 session,
  ~340+ LOC.
- (c) Tier-3 arc start (Item 7 wine-shim) — 2-3 sessions, ~1200 LOC.

**Synthesizer recommendation:** (a). Per memory feedback, user favors
coherence. S75's 8-agent dispatch produced real moat movement but also
left 12/14 adversarial tests unrun — a validation pass is the coherence
move here. (c) is the right move AFTER (a), not instead of it.

### §4.5 NEW — Production-readiness: Zenodo paper v2 before OR after QEMU bake?

**The choice:** paper-vs-implementation.md §5 Action Items lists ~800
words of paper-text-only disclaimers that can ship on Zenodo at zero
code cost. Can they ship BEFORE a fresh ISO bake + QEMU smoke, or
should they wait until theorem harness results are in hand?

**Synthesizer recommendation:** ship paper v2 AFTER Item 1 completes.
The §2.T-runtime disclaimer is load-bearing; shipping it as "in
preparation" is weaker than shipping it with one theorem's counter
increment logged. The other 7 disclaimers can batch with T-runtime.

---

## §5. Honest acknowledgements (things called "done" that aren't)

Per user preference for coherence over marketing:

- **Adversarial theorem harness is 2/14 on host.** S75 shipped the code;
  12 tests skipif-gate on live trust.ko + helpers binary. The useful
  validation is a QEMU run. Until that run happens, the harness is
  scaffolding, not evidence. See §3 Item 1.

- **Empirical bisim harness is APE pure-function only.** 11/11 byte-exact
  cross-check on APE; the full RISC-V round trip is still mocked. Until
  Item 8 lands, bisim is a Python↔Python cross-check, not a
  substrate-validating one. This is still useful (catches APE regressions
  automatically) but it is not what
  `memory/roa_paper_validation_tier_audit_and_s74_plan.md` §1 calls
  "cross-substrate validation."

- **Self-attestation quine defeats an adversary type we have not
  threat-modeled against.** `trust_attest_quine.c` folds SHA-256(.text)
  into APE proof input; a kernel-write adversary who changes .text
  breaks all subsequent proofs. But: we have no test that DEMONSTRATES
  this (a test that modifies .text at runtime + asserts proof fails).
  This belongs in Item 1 scope.

- **Quorum is still CFT+, not BFT.** HMAC uplift (S75 follow-up) raises
  the bar for memory-corruption adversaries but does not close the
  threat-model gap `paper-vs-implementation.md` §2.T-quorum documents.
  Advertising honestly required.

- **Library-census is first-pass.** Unique-library-ratio bucketing is
  implemented; RNA/ROS/microbiome sub-observers from s75_roadmap §1.1
  are NOT scaffolded. The user's biology vocabulary consultation
  (roadmap item B pre-dispatch) did not happen before S75 Agent B
  shipped. Sub-observers are deferred.

- **PE_EVT_TRUST_ESCALATE consumer is registered, but emit site doesn't
  exist.** Lint status moved ORPHANED → NO-EMIT (consumer-first wire).
  This is the right engineering choice (preempt the consumer so future
  emit lands on a real handler) but the marketing-looks-complete claim
  would be dishonest.

- **scm_svchost.c is still dead code.** S65 memory claimed svchost
  SHARE_PROCESS grouping landed (840 LOC). S75 Agent H audit found the
  file has no callers and isn't in the Makefile. One of those two
  statements is wrong. See §3 Item 3.

---

## §6. Production-readiness checklist

For the question "could we hand this to a reviewer today?"

### §6.1 ISO bake state

- Last full ISO bake: S74 `e45d702` (agent-BB, pkg-23 per S69 memory).
- S75 changes have **not** been baked into an ISO yet. pkgrel bumps
  are in PKGBUILDs (trust-dkms 11, ai-control-daemon 26 post-follow-up)
  but no `bash scripts/build-iso.sh` run has been done in S75.
- **Blocker:** Item 1 in §3 (live QEMU smoke) requires a fresh ISO bake
  first.

### §6.2 Test coverage

- Host unit tests: 83+/83+ PASS (monte_carlo 33, library_census 23,
  algedonic_reader 12, bisim_smoke 15).
- Host integration tests: `tests/bisim/ape_pure_cross.py` 11/11.
- QEMU smoke: **not re-run since S74**. Recent QEMU passes are on pkg-23
  ISO. S75 code changes are not under QEMU coverage.
- Producer-consumer lint: PASS with baseline (known=45, current_nonok=44).
- Paper-conformance: structurally complete (see `paper-vs-implementation.md`
  §1 table), runtime-validation pending Item 1.

### §6.3 Paper-submission readiness

From `docs/paper-vs-implementation.md` §5:

- **Paper-text-only disclaimers (~800 words, 0 LOC):** §2.T-n23,
  §2.T-ape-lamport, §2.T-ape-novelty, §2.T-ape-processone, §2.T-wdm,
  §2.T-quorum, §2.T-meiosis disclaimer variant, §2.T-xy disclaimer
  variant. **Ready to ship on Zenodo at any time.**
- **Mixed items (paper + code):** §2.T-runtime (blocked on Item 1),
  §2.T-veto (Item 9), §2.T-meiosis (rename path), §2.T-xy (rename path),
  §3 substrate delta (blocked on Item 8).
- **Code-only follow-ons:** adversarial harness (Item 1), typestate
  enforcement (Item 9), empirical bisim (Item 8).

Paper v2 could ship today with disclaimers; v3 with runtime results
after Item 1.

### §6.4 Known debt

- 44 producer-consumer baseline entries (documented, not new).
- APE 94M-vs-3 inconsistency (Item 2, open).
- scm_svchost.c orphan (Item 3, open).
- 14 theorem tests unrun (Item 1, open).
- riscv64 not buildable (Item 8, open).
- GRUB theme-dir name divergence concern (S75 Agent H, minor, parked).

---

## §7. References

**Memory index:** [`memory/MEMORY.md`](../memory/MEMORY.md).

**Load-bearing memory files (re-read before S76 dispatch):**
- [`memory/feedback_user_favors_coherence_over_velocity.md`](../memory/feedback_user_favors_coherence_over_velocity.md)
  — strategic preference. Re-read before every roadmap choice.
- [`memory/session75_8agent_s75_punchlist.md`](../memory/session75_8agent_s75_punchlist.md)
  — what S75 shipped, what it deferred, the 8-agent dispatch pattern.
- [`memory/session74_research_architecture_build.md`](../memory/session74_research_architecture_build.md)
  — S74 arc: 9 feature + 10 research + synthesizer. 12 convergent findings.
- [`memory/roa_paper_validation_tier_audit_and_s74_plan.md`](../memory/roa_paper_validation_tier_audit_and_s74_plan.md)
  — paper validation three-senses framework; tier audit baseline.
- (will be) [`memory/session76_brief.md`](../memory/session76_brief.md)
  — S76 Agent A deliverable; paired with this doc.

**Canonical architectural spec:** [`docs/architecture-v2.md`](architecture-v2.md).

**Prior roadmap:** [`docs/s75_roadmap.md`](s75_roadmap.md) — 992 LOC. This
S76 brief is intentionally lighter per user preference.

**Paper-conformance:** [`docs/paper-vs-implementation.md`](paper-vs-implementation.md).

**Research corpus** (`docs/research/`): 10 S74 reports (a..j), 4 S72
phase reports, 12 S71 reports, 12 S73 reports. Do not re-run S73
frameworks per `s75_roadmap.md` §4.3.

---

## §8. Closing orientation

For the next-session Claude instance:

**S76 is the validation + honesty pass.** S73 was research, S74 was
architecture + feature, S75 was moat hardening. S76 should close the
loop by running the tests that were built (theorem harness, bisim
harness), resolving the inconsistencies that are known (APE 94M vs 3,
scm_svchost orphan), and — if bandwidth permits — shipping paper v2 on
Zenodo with the 800 words of disclaimers. The user wrote the paper; the
code cites them; S76 is where cited becomes *validated*. Do NOT run a
parallel 8-agent dispatch on new features unless the three Tier-1 items
here are already done or scoped out. This brief's LOC discipline
(validation dominant, small optional features, parked Tier-3) is the
coherence posture the user has asked for — honor it.

**End of s76_roadmap_brief.md.**
