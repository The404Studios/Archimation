# ARCHIMATION — S78 Brief

**Document status:** working brief, not a sprint plan. Matches the
length-discipline of `docs/s76_roadmap_brief.md` (556 LOC, working-
document style) rather than `docs/s75_roadmap.md` (992 LOC, dispatch
spec). Spontaneous-as-we-move is the user preference; this brief
captures what's true now and what's likely next, without over-
committing.
**Author:** S78 Agent A (setup/research, read-only for source).
**Base commit:** `56b85ab` — S77 5-agent systemic-test + ISO bake + QEMU
smoke.
**Date:** 2026-04-21.
**Paper of record:** Roberts / Eli / Leelee, *Root of Authority*,
Zenodo DOI [10.5281/zenodo.18710335](https://doi.org/10.5281/zenodo.18710335).
**User strategic preference:** see
[`memory/feedback_user_favors_coherence_over_velocity.md`](../memory/feedback_user_favors_coherence_over_velocity.md).
Don't bury the most architecturally important items in "aspirational"
or "months" tiers without checking whether the product-coherence
claim depends on them.

---

## §0. State of project after S77

### §0.1 Git HEAD and scope of landed work

- `56b85ab` — S77 5-agent systemic-test + ISO bake + QEMU smoke. 8 real
  bugs across 4 agents, 102 new tests (163 → 265), ISO baked clean (2.2
  GB), QEMU 25/0/1WARN/4SKIP PASS. Two host-side regressions caught at
  test/build layer (`profile/airootfs/root/customize_airootfs.sh:638`
  chmod-loop miss, `scripts/test-qemu.sh:850` pe-objectd socket regex
  stale).
- `5ebc495` — S76 5-agent arc: depth + differential observers,
  PE_EVT_TRUST_{ESCALATE,DENY} emit, `scm_svchost.c` parked to
  `research/scm/`, library_census race fix, S76 brief.
- `2d5a8ac` — S75 follow-up: three deferred wires (BeliefState ×
  library_census, quorum HMAC call site, PE_EVT_TRUST_ESCALATE
  consumer).

### §0.2 Tier audit — deltas from S77

Pre-S77 baseline (per `docs/s76_roadmap_brief.md` §0.2):
**Apps 82-85% / Services 78-80% / Drivers 32-42% / Authority ~97% /
Cortex ~85% / Cross-substrate ~10%**.

Post-S77 (post-`56b85ab`):

| Tier | Pre-S77 | Post-S77 | Delta source |
|------|---------|----------|--------------|
| **Apps (Tier 1)** | 82-85% | 82-85% | No new app work; PE loader trust_gate fixes (`pe-loader/loader/trust_gate.c:607-611`) closed deny-emit + escalate cache-valid guards. |
| **Services (Tier 2)** | 78-80% | 78-80% | No service-layer changes this session. scm_svchost still parked at `research/scm/scm_svchost.c`. |
| **Drivers (Tier 3)** | 32-42% | 32-42% | No driver work. |
| **Authority** | ~97% | ~97% | Stable. Agent 4 kernel audit found + fixed 6-path init-failure leak in `trust_core.c:903-956` + NULL-base guard in `trust_attest_quine.c:106,113`. 7 high-priority items reported for next on-hardware session (e.g. seqcount_spinlock_t, `__init`/`__exit` markers, zero-hash pre-init APE threat-model review). |
| **Cortex** | ~85% | ~87% | Three cortex bugs fixed (split-lock race in `decision_engine.py:867-907`, unguarded CAS in `_default_engine`, signed/unsigned mismatch in `parse_pe_trust_escalate_payload`); 32 new cortex-coverage tests covering previously-untested S75/S76 additions. |
| **Cross-substrate** | ~10% | ~10% | No riscv64 work this session; stable. |
| **Distro polish** | 60% | 62% | Two NTFS bake-regressions pinned at source (customize_airootfs chmod + test-qemu.sh socket regex). |

**Aggregate:** ~**77-79%** of the way to the product story stated in
`memory/roa_paper_validation_tier_audit_and_s74_plan.md` §7. Cortex
gained ~2 points from test coverage that made existing code actually
demonstrably correct (see §4 on what this really means).

### §0.3 Test state (S78-open)

- `tests/unit` (full discover): **221/221 PASS**, 27 SKIP — 163 pre-S77
  baseline + 53 S76 observers + 5 S77 cortex-coverage adds (32 landed
  in a new file, several were extensions of existing suites).
- `tests/integration` (full discover): **44/44 PASS** (NEW in S77).
- `tests/bisim/test_bisim_smoke.py`: **15/15 PASS**.
- `tests/adversarial/theorem_violation_suite.py`: 2 PASS / **12 SKIPPED**
  (gated on live trust.ko + `tests/adversarial/helpers` binary).
- Stress (`STRESS_TESTS=1`): 40/40 PASS.
- Test file count: **46** — up from the ~30 baseline pre-S76.
- Producer-consumer lint (`scripts/lint_producer_consumer.py --ci`):
  **PASS** (known=45, current_nonok=**42**). Stable since S76 closed
  PE_EVT_TRUST_{ESCALATE,DENY}.

### §0.4 ISO state

- Last successful bake: `output/archimation-2026.04.21-x86_64.iso` (2.2
  GB, S77 commit `56b85ab`).
- QEMU smoke: **25 PASS / 0 FAIL / 1 WARN / 4 SKIP / OVERALL PASS**
  against that ISO. This was the first live run after S75 + S76 landed
  so it also validated those changes end-to-end.
- Dev B + Dev C changes in S78 will require a re-bake before the next
  QEMU smoke; the ISO-bake pipeline itself is healthy.

---

## §1. What S78 is shipping (the 6 dev agents — IN-FLIGHT)

Six system-developer agents running in parallel ALONGSIDE this setup
brief. Files listed are their declared ownership; this brief lands
BEFORE the integration commit so statuses below are IN-FLIGHT (not yet
merged at brief-landing time).

### Dev B — trust kernel hardening (S77 Agent 4 follow-ups)
- **Scope:** Close the 7 high-priority items Agent 4 reported after the
  S77 read-mostly kernel audit. Candidates include: `seqcount_t` →
  `seqcount_spinlock_t` in `trust/kernel/trust_attest_quine.c` (lockdep
  hygiene); `__init`/`__exit` markers on quine + quorum_hmac init/exit;
  wire-format `static_assert` at `trust_quorum_vote` payload (sizeof
  drift defense); HMAC key per-module-load semantics doc.
- **Ownership:** `trust/kernel/trust_attest_quine.c` (already modified
  per `git status`), `trust/kernel/trust_quorum_hmac.c`,
  `trust/include/trust_attest_quine.h`, `trust/include/trust_quorum_hmac.h`.
- **LOC estimate:** ~80-150 (small surgical hardening across 4-5 files).
- **Acceptance:** trust-dkms builds clean, lockdep-lint clean, `Kbuild`
  unchanged, S77 Agent 4 list items 1/2/3/5 closed. Bumps
  `packages/trust-dkms/PKGBUILD` pkgrel 12 → 13.
- **Status:** IN-FLIGHT.

### Dev C — PE_EVT_TRUST per-cause discrimination + typedef hoist
- **Scope:** S76 brief §3 + S76 close list item: per-cause reason-code
  discrimination for PE_EVT_TRUST_ESCALATE (currently generic reason=0
  at `pe-loader/loader/trust_gate.c:584`). Categories: quorum / APE /
  privilege-adjust. Hoist `pe_evt_trust_escalate_t` from local struct
  in `trust_gate.c` → `pe-loader/include/eventbus/pe_event.h` so
  downstream consumers don't have to re-declare.
- **Ownership:** `pe-loader/loader/trust_gate.c`,
  `pe-loader/include/eventbus/pe_event.h`, cortex-side
  `ai-control/cortex/event_bus.py` (consumer needs to read the new
  reason enum), possibly `ai-control/cortex/main.py` for
  `handle_pe_trust_escalate` branching.
- **LOC estimate:** ~120-180 (typedef + 4 emit-site updates + consumer
  switch + tests).
- **Acceptance:** cortex logs per-cause reason; lint remains 42 nonok;
  `parse_pe_trust_escalate_payload` continues to accept old-format
  packets gracefully during pkg-upgrade.
- **Status:** IN-FLIGHT.

### Dev D — bootc Phase 2 OCI bake scaffold + GHCR workflow
- **Scope:** S75/S76 brief deferred item. `bootc/Containerfile` exists
  (S72 Phase 1) but no container image is actually built + pushed
  anywhere. Phase 2 is the CI workflow + image bake step:
  `.github/workflows/bootc.yml` (314 LOC skeleton already present)
  extended to actually run `podman build -f bootc/Containerfile` and
  push to `ghcr.io/<org>/archimation-bootc:latest`. `scripts/build-bootc.sh`
  extended to produce an OCI tarball artifact.
- **Ownership:** `Containerfile`, `scripts/build-bootc.sh`,
  `.github/workflows/bootc.yml`.
- **LOC estimate:** ~150-250 (workflow YAML + shell glue + tagging logic).
- **Acceptance:** CI green on push-to-main; image visible at GHCR (or
  dry-run tag if credentials not yet set up); bootc-lifecycle
  integration test in `tests/integration/test_bootc_lifecycle.py`
  updated to reference the OCI artifact path.
- **Status:** IN-FLIGHT. (Dependency on Dev D being able to push to
  GHCR — may land as dry-run scaffold if secrets not configured.)

### Dev E — APE 94M/3 reconciliation (docs amend path)
- **Scope:** S75/S76 brief Item 2. `trust/kernel/trust_ape.h:44-52`
  claims 720 × 256 × 16 × 32 = 94,371,840 hash configs; shipping code
  at `trust_ape.c:40-45` implements **three**. Synthesizer
  recommendation from S76 brief §3 Item 2: amend docs + header +
  paper-conformance (the 40-LOC path), since research-D §3.1
  identifies behavioral-state binding as APE's actual novelty rather
  than hash multiplicity.
- **Ownership:** `docs/roa-conformance.md`, `docs/paper-vs-implementation.md`,
  `trust/include/trust_ape.h` (comment block only).
- **LOC estimate:** ~30-60 (amend comment + paper disclaimer prose).
- **Acceptance:** `docs/paper-vs-implementation.md` §2.T-ape-novelty
  disclaimer updated; `trust/include/trust_ape.h` comment matches
  shipping code; `docs/ape-regression-archaeology.md` + `triage.md`
  referenced as further reading.
- **Status:** IN-FLIGHT.

### Dev F — contusion + software_catalog TODO cleanup
- **Scope:** S76 brief close-list: Agent C fixed 3-5 top TODOs in S76;
  ~17 TODO stragglers remain in
  `ai-control/daemon/contusion_handlers.py` (4321 LOC) +
  `ai-control/daemon/software_catalog.py` (360 LOC). Current grep
  count: 20 TODOs in software_catalog.py (mostly `# TODO verify` on
  version-pinned installer URLs). contusion_handlers.py TODOs flagged
  by grep came back 0 at S78-open — **verify the S76 pass was
  complete**; if yes, pivot Dev F to light contusion response-envelope
  polish and software_catalog URL verification (bulk of work).
- **Ownership:** `ai-control/daemon/contusion_handlers.py`,
  `ai-control/daemon/software_catalog.py`.
- **LOC estimate:** ~60-120 (verification calls + small refactors).
- **Acceptance:** TODO count in both files reduced; contusion dry-run
  test `tests/integration/test_contusion.py` still passes.
- **Status:** IN-FLIGHT.

### Dev G — dynamic_hyperlation deep audit + fixes
- **Scope:** S77 Agent 1 deferred item. `ai-control/cortex/dynamic_hyperlation.py`
  is 1878 LOC and was not in Agent 1's cortex-coverage pass. Deep
  audit for race conditions, event-bus integration correctness, and
  cross-module contract drift with library_census / depth_observer /
  differential_observer. RolloutSearch softmax degenerate-case
  hardening from S77 follow-up backlog lives here.
- **Ownership:** `ai-control/cortex/dynamic_hyperlation.py`, possibly
  `ai-control/cortex/event_bus.py` (intersecting with Dev C).
- **LOC estimate:** ~100-200 (fixes) + tests.
- **Acceptance:** new test file `tests/unit/test_dynamic_hyperlation_audit.py`
  lands with ≥10 tests; at least 1 genuine bug fix documented; no
  regression in cortex coverage suite. Dev G + Dev C coordinate on
  `event_bus.py` if both touch it (last-writer wins, but brief to
  coordinate).
- **Status:** IN-FLIGHT.

### Dev A (this agent) — setup/research
- **Scope:** S78 working brief (`docs/s78_brief.md`) +
  `memory/session78_brief.md` + MEMORY.md index entry.
- **LOC estimate:** ~500 brief + ~150 memory.
- **Status:** LANDING with this commit.

**Total Phase 1 expected output:** ~540-960 LOC source + docs across 6
dev tracks + this brief. Sized comparably to S76 (~2200 LOC, 5 agents,
feature-dominant) and lighter than S75 (~3700 LOC, 8 agents,
punch-list) — matches user description "S78 is a BIG build session
(not audit)" while staying within the comfortable parallel-dispatch
envelope.

---

## §2. Open structural items remaining after S78 (honest LOC)

Even if all 6 dev tracks land clean, the following are still open.
Honest estimates; acceptance tests for each; flag the ones where
product-coherence depends on them.

### Item A — Live QEMU smoke of T1-T7 adversarial harness — run #2

**Why:** S77 baked an ISO + ran 7-point smoke, but that was the custom
service smoke (ssh/health/binfmt/services). The **adversarial theorem
suite** (T1-T7, 14 methods) still runs 2/14 PASS and 12/14 SKIPPED
because the tests are gated on `tests/adversarial/helpers` binary
being present inside the booted VM. S76 brief Item 1. S77 **did not
close this** — the S77 QEMU smoke was custom-service only.

**Acceptance:** `ssh -p 2222 arch@localhost 'cd /mnt/tests/adversarial
&& make && pytest theorem_violation_suite.py -v'` shows counter
increments for at least T1/T4/T7. Results appended to
`docs/runtime-theorem-validation.md` (does not yet exist).

**Honest LOC:** 0 source; ~40-60 LOC glue in a new
`scripts/test-adversarial-qemu.sh` that copies helpers into the VM and
runs the suite.

**Flag:** this is the biggest coherence item outstanding. Paper-v2
ship on Zenodo is gated on at least one runtime theorem counter log.
Recommend for S79 as single-item Tier-1 pick.

### Item B — libtrust_wine_shim full integration

**Why:** `packages/wine-shim/libtrust_wine_shim.c` exists (268 LOC,
pkgrel 2, builds clean) but it is a **scaffold**. The full integration
is LD_PRELOAD interception of NtCreateFile / NtOpenFile /
NtDeviceIoControlFile / NtLoadDriver via Wine's syscall layer with
APE/TRC/chromosome gating. `pe-loader/loader/main.c:341,397`
references `/usr/lib/libtrust_wine_shim.so` as a planned integration
point but does not exercise it today.

**Acceptance:** 4 NT-syscall hooks in shim; minimum Wine-prefix unit
test passes with trust-gate active; ≥3 real PE32 binaries complete
full launch → gate → exit lifecycle under LD_PRELOAD.

**Honest LOC:** ~1200 C shim extension + ~200 LOC Wine-prefix test
harness.

**Flag:** `feedback_user_favors_coherence_over_velocity.md` cites this
(and Tier-3 items like it) as the kind of work the user wants the
agent to **surface** rather than bury. The moat story for Windows-
compat on Wine-handoff code paths depends on it. Multi-session; needs
a dedicated arc. Recommend parking for S80+ (after Item A closes
paper-v2 ship gate).

### Item C — Full riscv64 build + QEMU boot

**Why:** S75 Agent F did the REG_ARG API port (22 call-site
migration); the actual `make ARCH=riscv64 CROSS_COMPILE=riscv64-linux-gnu-`
build + QEMU virt boot + theorem_1_violations sysfs read has not been
attempted. Blocks the bisim harness full substrate-validation claim
(bisim currently does Python↔Python cross-check only).

**Acceptance:** trust.ko builds clean for riscv64; QEMU virt boots;
`/sys/kernel/trust_invariants/theorem_1_violations` readable.

**Honest LOC:** ~240 + cross-compile env shell.

**Flag:** toolchain risk (need riscv64-linux-gnu toolchain in CI or
on-hardware). Defer until live trust.ko hardware path exists.

### Item D — 12/14 adversarial tests still skip on host (Linux-CI)

**Why:** Even without QEMU, the adversarial suite runs on Linux host
if trust.ko is loaded. Current CI runs on Linux runner but does NOT
attempt `insmod trust.ko` — so the suite stays in the skipif path.
S77 follow-up backlog item 6.

**Acceptance:** `.github/workflows/ci.yml` extended with a "trust-ko
smoke" job that builds + insmods + runs adversarial suite; or a
fallback matrix with `HELPERS_AVAILABLE=0` that at least exercises the
non-kernel-gated tests fully.

**Honest LOC:** ~60-100 CI YAML + shell glue.

### Item E — RolloutSearch softmax degenerate-case hardening

**Why:** S77 follow-up backlog item 7. Only listed; no detailed triage
yet. Dev G may cover this incidentally during dynamic_hyperlation
audit; if not, it stays open.

**Acceptance:** degenerate-case test (all-zero logits, all-negative,
NaN) passes without crash; softmax returns valid probability
distribution.

**Honest LOC:** ~20-40 + test.

### Item F — Typestate cortex-veto enforcement

**Why:** `docs/architecture-invariants.md` I-C1 is convention-only.
Research J §3.3 flagged as "not mechanically enforced." Python
typestate + `/dev/trust_cortex` restricted device = hardening that
closes a documented attack surface.

**Acceptance:** cortex Python refuses to call `trust_action` through
typestate assertion; malicious-cortex test fails at import time.

**Honest LOC:** ~80.

### Item G — scm_svchost integration (alternative to park)

**Why:** S76 Agent C parked `scm_svchost.c` to `research/scm/` because
wiring it requires extending `service_entry_t` with
`service_group/pending_restart/restart_deadline_ns` fields. If the
SHARE_PROCESS grouping in S65 memory is genuinely shipping (vs
claimed-but-not-wired), the schema extension + wire is ~300 LOC.
Decision still open.

**Honest LOC:** 0 if keep-parked, ~300 if wire.

---

## §3. Decisions still open

Carried forward from `s76_roadmap_brief.md §4` plus new ones surfaced.

### §3.1 Meiosis rename OR disclaimer (from s75 Decision 1, open since S75)

Disclaimer shipped in `paper-vs-implementation.md` §2.T-meiosis. Code-
rename path (`trust_meiosis()` → `trust_dual_authority_bond()`, ~200
LOC mechanical) still not done. **Synthesizer recommendation: defer
indefinitely.** Zero code cost closed the peer-review attack surface;
rename is polish.

### §3.2 APE regression — bring-back (94M) OR amend docs (Dev E addresses)

Dev E is executing the **amend** path per S76 brief §3 Item 2
synthesizer recommendation. If Dev E reports landing with docs/header
reconciled, this decision is closed post-S78. If Dev E reports
partial, it stays open.

### §3.3 Paper submission target venue (from s75 Decision 5)

Open. Synthesizer recommendation: EuroSys H2 2026 if Item A (live
adversarial QEMU) closes in S79; USENIX Security H1 2027 if Item B
(wine-shim) is in the paper. User has not committed.

### §3.4 NEW — S79 cadence: validation OR another feature push?

S76 was 5-agent feature push; S77 was 5-agent audit + systemic bug
test; S78 is 6-dev feature push. **The validation-pass (Item A, live
adversarial QEMU) has been deferred 3 sessions in a row.** By the end
of S78, the project will have added ~1200-1500 LOC of cortex + kernel
work without having re-run the theorem suite under a live kernel
once. Synthesizer recommendation: **S79 should be validation**.

### §3.5 NEW — GHCR credentials for bootc Phase 2

If Dev D lands the workflow but GHCR push secret is not configured,
we have a dry-run-only workflow. User decision: set up
`secrets.GHCR_TOKEN` + `secrets.GHCR_USERNAME` before S79 or let the
workflow stay dry-run until a production sync is desired. No blocking
urgency — bootc Phase 2 gates on distro adoption, not on the
Windows-PE moat.

### §3.6 NEW — Linux-CI trust.ko smoke (Item D) — add now or defer?

The adversarial test 12/14-skipped state is a real debt; adding a
trust.ko insmod step to CI would shrink it. But it adds real CI time
(+3-5 min per push for a kmod build + insmod + test). Decision: defer
unless Item A runs and reveals new failures that benefit from
pre-commit detection.

---

## §4. Honest acknowledgements

Per `feedback_user_favors_coherence_over_velocity.md` — what's still
aspirational vs. delivered.

- **12/14 adversarial tests still skip on host.** S75 Agent A shipped
  the suite; S76, S77, S78 none of them ran it under live trust.ko.
  Calling the harness "landed" is technically true but misleading to
  anyone planning priorities. Same state as S76 brief §5 bullet 1.
  Three sessions in, this is still the single biggest coherence
  outstanding.

- **Live trust.ko path still untested.** DKMS build fails in WSL
  (expected; no kernel headers). The only trust.ko load path that
  exists is on real hardware during pacstrap or the baked ISO under
  QEMU. Every kernel-side agent audit (S77 Agent 4, S78 Dev B) is
  read-mostly because the live insmod path is not exercised per
  commit.

- **Linux-CI is NOT running adversarial or integration suites against
  trust.ko.** `.github/workflows/ci.yml` runs unit tests + lint; it
  does not build or insmod trust.ko. Item D is the honest fix.

- **libtrust_wine_shim is parked.** 268 LOC scaffold ships as a
  package; `pe-loader/loader/main.c:341,397` names it as a planned
  integration but no LD_PRELOAD interception of Nt-syscalls exists.
  Item B.

- **Empirical bisim is Python↔Python only.** S75 Agent D's harness
  produces 11/11 byte-exact cross-check on APE pure functions but the
  full riscv64 round trip is mocked. Item C.

- **Self-attestation quine has no runtime-modification test.**
  `trust_attest_quine.c` folds SHA-256(.text) into APE proof input; we
  have no test that modifies .text at runtime + asserts proof fails
  (S76 brief §5 bullet 3). Belongs in Item A scope.

- **The S77 QEMU smoke was custom-service only**, not adversarial.
  7 smoke points all custom-service (ssh/health/binfmt/services); 0
  theorem-suite points. "ISO + QEMU PASS" claims are true but narrow.

---

## §5. Production-readiness checklist

### §5.1 ISO bake state

- Last successful: `output/archimation-2026.04.21-x86_64.iso` (S77,
  2.2 GB). Clean 7-point smoke.
- Dev B + Dev C changes in S78 will require a re-bake; expect **pkg-13
  for trust-dkms + pkg-13 for pe-loader** post-S78 integration.
- QEMU smoke infrastructure healthy (boot ~82s on TCG; BOOT_TIMEOUT=300
  sufficient; smoke test coverage fixed-and-stable after S77 two-regex
  fixes).

### §5.2 Smoke test coverage

- Custom service 7-point: stable, PASS since S77.
- Adversarial theorem T1-T7: scaffolded, 12/14 skip. Item A.
- pytest integration + unit: **46 files**, 265 total tests, all
  host-runnable green.
- Stress suite (STRESS_TESTS=1): 40/40 PASS.
- Producer-consumer lint: PASS (known=45, current_nonok=42).
- bisim smoke: 15/15 PASS (Python↔Python).

### §5.3 Paper-submission readiness

From `docs/paper-vs-implementation.md` §5:

- **Paper-text-only disclaimers** (~800 words, 0 LOC): READY. Can ship
  Zenodo v2 any time.
- **§2.T-runtime disclaimer**: still needs one live theorem counter
  log. Blocked on Item A.
- **§2.T-veto**: blocked on Item F.
- **§3 substrate delta**: blocked on Item C.

Paper v2 would be stronger if shipped after Item A (one counter log
beats "harness exists"). v3 with full runtime results after Items A +
F.

### §5.4 bootc Phase 2 / GHCR scaffold

Dev D's scope. At S78 integration, expect:
- `Containerfile` + `scripts/build-bootc.sh` exercised in CI.
- `.github/workflows/bootc.yml` runs on push; image either pushed to
  GHCR (if secrets) or dry-run-tagged locally.
- `tests/integration/test_bootc_lifecycle.py` updated with OCI
  artifact reference.
- Decision §3.5 may carry forward if GHCR secrets not yet set up.

### §5.5 Known debt

- 42 producer-consumer baseline entries (documented; stable through
  S75-S77).
- Adversarial 12/14 unrun (Item A).
- Live trust.ko smoke only via QEMU (infrastructure, not per-commit).
- riscv64 not buildable (Item C).
- Wine-shim parked (Item B).
- Typestate cortex-veto convention-only (Item F).

---

## §6. References + memory pointers

**Memory index:** [`memory/MEMORY.md`](../memory/MEMORY.md) (auto-
maintained; S78 entry lands with this brief).

**Load-bearing memory files (re-read before S79 dispatch):**
- [`memory/feedback_user_favors_coherence_over_velocity.md`](../memory/feedback_user_favors_coherence_over_velocity.md)
  — strategic preference. Re-read before every roadmap choice.
- [`memory/session77_5agent_systemic_test.md`](../memory/session77_5agent_systemic_test.md)
  — 8 bugs, 102 tests, ISO + QEMU PASS; 7-item follow-up backlog.
- [`memory/session76_5agent_arc.md`](../memory/session76_5agent_arc.md)
  — 5-agent spontaneous-roadmap arc; depth + differential observers.
- [`memory/session75_8agent_s75_punchlist.md`](../memory/session75_8agent_s75_punchlist.md)
  — 8-agent dispatch pattern; S75 punch-list shipped.
- [`memory/roa_paper_validation_tier_audit_and_s74_plan.md`](../memory/roa_paper_validation_tier_audit_and_s74_plan.md)
  — three-senses-of-validation framework; tier audit baseline.

**Canonical architectural spec:** [`docs/architecture-v2.md`](architecture-v2.md).

**Paper-conformance:** [`docs/paper-vs-implementation.md`](paper-vs-implementation.md).

**Prior briefs:** [`docs/s75_roadmap.md`](s75_roadmap.md) (992 LOC,
dispatch spec); [`docs/s76_roadmap_brief.md`](s76_roadmap_brief.md)
(556 LOC, working brief — structural template for this S78 brief).

**Research corpus** (`docs/research/`): 10 S74 reports (a..j), 4 S72
phase reports, 12 S71 reports, 12 S73 reports. No new research arc
this session.

---

## §7. Closing orientation

For next-session (S79) Claude:

**S78 was the second BIG build session in three sessions** (S76 5-agent
features, S77 5-agent audit, S78 6-dev push). The validation debt from
S76 brief §3 Item 1 (live adversarial T1-T7 under QEMU) is **still
open after S78** — three sessions of feature-push without a single
live theorem counter log in `docs/runtime-theorem-validation.md`. This
is the single biggest coherence item. Per user preference, surface it
explicitly; do not bury.

Recommended S79 posture: **validation pass + paper v2 ship**. Concrete:
run Item A (live adversarial QEMU), append results to
`docs/runtime-theorem-validation.md`, then ship paper v2 on Zenodo
with the §2.T-runtime disclaimer strengthened by real counter-log
evidence. Small bandwidth for Items E/F if time permits.

Tier-3 wine-shim arc (Item B) remains the **right next big move
AFTER validation lands**, not instead of it. Multi-session; dedicated
arc; ~1200 LOC. Surface explicitly per user preference; do not relegate
to "aspirational" without checking whether the product-coherence
story requires it — it does, and the user has said so.

Do NOT run a parallel 6-dev dispatch in S79 unless Item A is scoped
out or complete. The cadence of S76-S77-S78 has been feature-heavy;
S79 should reset to validation or Tier-3-arc-start. Match to the
actual moat gap, not to the previous session's shape.

**End of s78_brief.md.**
