# Runtime Theorem Validation — Adversarial Harness Specification

**Document purpose.** Specify (do not implement) the adversarial test
harness that deliberately attempts to violate each of the Root of
Authority paper's seven security theorems, and verifies that the
corresponding sysfs counter fires.

**Status.** S74 research deliverable, Agent L. The actual
implementation is **S75 work** per architecture-v2.md §8 row 6
(~800 LOC, single agent, 1-2 sessions).

**Research citations.** D §1.5 (T3 chi-square witness is point-test
only), G §0 + §2.3 + §2.4 (quorum threat model / runtime validation
gap), J §3.3 + §5 Proposal A (adversarial theorem harness is highest-
ROI single move for S75).

**Companion documents.** `docs/paper-vs-implementation.md` §2.T-runtime
(required paper disclaimer), `docs/architecture-invariants.md` §3
(invariant I-3 mitotic/meiotic decay check).

---

## §0. Motivation — why this harness is the highest-ROI next step

### Current state

The seven Root of Authority security theorems
(`trust/include/trust_theorems.h:5-6`, citing Zenodo 18710335 §Security
Theorems 1-7) have **sysfs counters** at `/sys/kernel/trust_invariants/`:

- `theorem1_violations` — T1 Non-Static Secrets
- `theorem2_violations` — T2 Non-Replayability
- `theorem4_violations` — T4 Bounded Authority Inheritance
- `theorem5_violations` + `theorem5_max_us` — T5 Guaranteed Revocation
  O(1)
- `theorem6_violations` — T6 Metabolic Fairness

(T3 Forward Secrecy and T7 Statistical Anomaly Detection are statistical
statements over an indefinite history and not runtime-checkable as
point predicates. See §2.T3 and §2.T7 below for how they are exercised
anyway.)

The counters **have never been observed non-zero under clean load**.

### The gap

The counters work — we can increment them manually from a test. The
question is: **would they fire under a real violation attempt?** That is
the difference between structural validation and runtime validation.
Per research D §1.5 the SHA-256-only chi-square witness for T3 is
openly caveated as a *lower bound test*, not a composite-chain proof.
Per research G §0 the quorum's "23 replicas" are in one struct and
kernel-write flips them all in one move. Per research J §3.3:

> "Trust.ko has never been run against a red-team. Its seven sysfs
> violation counters have sat at 0 under clean load. S73-F's self-
> attestation idea is the only thing that would force a live
> violation; it's still aspirational. **This is the biggest gap
> between our self-perception and our defensible claim.**"

### What the harness does

For each theorem:

1. **Construct an adversary** that explicitly attempts to violate the
   theorem.
2. **Drive the adversary** against a running `trust.ko` instance.
3. **Verify three things:**
   - The violation attempt is **refused** (kernel does not grant the
     violation).
   - The corresponding sysfs counter **increments**.
   - No privilege escape occurs (the adversary does not gain
     authority it should not have).

### Why this is the highest-ROI S75 move

- **Turns "asserted" into "demonstrated."** Every peer-review
  conversation starts from a stronger footing.
- **Cheap:** ~800 LOC total per research J §5 Proposal A. Fits one
  agent, 1-2 sessions.
- **Compounds:** once wired, every new security-sensitive change
  re-runs the harness automatically in CI. Protects against
  regression.
- **Unique:** no other Linux-security project has this specific
  theorem set, so no off-the-shelf harness exists — but also no
  competitor can casually claim parity.

---

## §1. Test-harness architecture

### Orchestrator

```
scripts/test-roa-theorems.sh
└─ invokes pytest on tests/adversarial/theorem_violation_suite.py
   └─ 7 test classes (one per theorem)
      └─ each test class has multiple test methods
         (different violation strategies for the same theorem)
```

### File layout (proposed)

```
tests/adversarial/
├─ README.md                        -- 1-page overview
├─ __init__.py
├─ conftest.py                      -- pytest fixtures
├─ theorem_violation_suite.py       -- 7 test classes, ~500 LOC
├─ harness/
│  ├─ __init__.py
│  ├─ counters.py                   -- sysfs counter snapshot/diff, ~40 LOC
│  ├─ subject_factory.py            -- creates/destroys test subjects, ~60 LOC
│  ├─ proof_replay.py               -- captures/replays APE proofs, ~80 LOC
│  ├─ kprobe_tap.py                 -- attaches kprobes to enumerate leak paths, ~60 LOC
│  └─ entropy_sampler.py            -- samples CRNG + proof outputs for χ², ~50 LOC
└─ kernel_shim/
   └─ test_shim.c                   -- kernel module + debug sysfs, ~180 LOC
```

### Counter-value comparison

Every test follows this pattern:

```python
def test_Tx_attack_strategy_N(harness):
    before = harness.snapshot_counters()
    outcome = harness.attempt_violation_strategy_N()
    after = harness.snapshot_counters()
    delta = after - before

    assert outcome.refused, "kernel should have refused this violation"
    assert delta.theoremX_violations > 0, "counter did not fire"
    assert not outcome.escalated_authority, "privilege escape detected"
```

---

## §2. Per-theorem test specification

### §2.T1 — Non-Static Secrets

**Theorem statement.** No sysfs / debugfs / `/proc` / ioctl path exists
that exfiltrates SEED, PROOF (pre-consumption), or hash_cfg state from
a live subject.

**Counter:** `/sys/kernel/trust_invariants/theorem1_violations`.

**Adversary model.** Userspace attacker with `CAP_SYS_ADMIN` but
without kernel-write capability. Tries every enumerable read path to
extract secret material.

**Test strategies:**

1. **Sysfs surface scan.** Walk `/sys/kernel/trust*/*` recursively;
   read every file. For each: (a) assert no 32-byte aligned region
   matches a known SEED value; (b) assert no 32-byte aligned region
   matches a captured `P_n` value; (c) assert no "hash_cfg" string
   indicates the current config selector.

2. **Debugfs surface scan.** Same walk under `/sys/kernel/debug/
   trust*/` (where `CONFIG_DEBUG_FS=y`). Expected: the whole trust
   subtree either does not expose secret material at all, or the
   subtree is gated by `CONFIG_DEBUG_TRUST_EXPOSE_STATE` (CI must fail
   if this is `y`).

3. **Proc walk.** `/proc/<pid>/maps`, `/proc/<pid>/mem` (with
   `ptrace(PTRACE_ATTACH)`), `/proc/kcore`, `/proc/kallsyms`. For
   each: scan for byte-patterns matching known SEED / PROOF values.

4. **ioctl fuzzer.** Enumerate every ioctl opcode on `/dev/trust`,
   including undocumented ones. For each opcode, feed buffers of
   varying sizes and flag bits. Verify no response returns
   known-secret bytes.

5. **BPF tracer.** `bpftrace -e 'kprobe:trust_ape_* { printf(...) }'`.
   Attach to every exported `trust_ape_*` symbol. Walk state after
   subject create, after consume, after destroy. Verify no live
   memory dump contains decrypted SEED outside the spinlock-held
   regions.

**Success criterion.** Counter stays at 0. No secret bytes leak.

**Failure criterion.** Any path returns a known-secret byte sequence.
Counter increment is NOT expected — a leak is a different kind of
failure than an attempted violation. Strategy: if a leak is found,
the test records a specific counter bump via a deliberate bump helper,
then fails with a detailed report.

**LOC estimate.** ~150 (strategies 1-5 combined).

---

### §2.T2 — Non-Replayability

**Theorem statement.** A proof `P_n` consumed at time `t` cannot be
re-used at time `t' > t`. The global nonce advances monotonically.

**Counter:** `/sys/kernel/trust_invariants/theorem2_violations`.

**Adversary model.** Userspace attacker that captures a valid proof
(via legitimate ioctl path) and attempts to submit it a second time.

**Test strategies:**

1. **Simple replay.** Create subject, consume proof (returns valid
   verdict), re-submit the *same* proof bytes. Expect refusal + counter
   increment.

2. **Delayed replay.** Consume proof at `t`, sleep 1s, re-submit at
   `t+1s`. Same expectation. (Tests that refusal is not timing-
   sensitive.)

3. **Post-chain replay.** Consume proof at `t`, advance chain by 10
   legitimate consumes, replay original `P_0` at `t+Δ`. Tests that
   refusal does not depend on chain position being fresh.

4. **Nonce rollback via kernel-write.** (Requires `CONFIG_DEBUG_TRUST
   _WRITE_TEST=y`.) Write the global nonce backward from value `N` to
   `N-1` via a debug ioctl. Consume a proof. Expect: counter
   increment AND proof refused (the monotonicity check catches it).

5. **Cross-subject replay.** Capture proof from subject A, submit as
   subject B. Expect refusal — proofs are per-subject.

**Success criterion.** Each strategy: refused + counter increments.
Strategy 1 is the simplest; strategies 2-5 test the refusal is robust
against timing / chain-depth / privileged-path / cross-subject
confusions.

**LOC estimate.** ~100.

---

### §2.T3 — Forward Secrecy (statistical)

**Theorem statement.** The proof chain output distribution is
statistically indistinguishable from uniform over the output space.
A compromised `P_n` does not reveal `P_{n-k}` for any `k > 0`.

**Counter:** None (T3 is statistical, not runtime-checkable as a
point predicate). **This test has no built-in counter comparison.**

**Adversary model.** Observer who captures 1 hour of proof-chain
output under varied input and attempts to detect non-uniformity.

**Test strategies:**

1. **Chi-square over composite chain.** Per research D §1.5, the
   existing `trust_ape_markov.c` runtime witness tests SHA-256 ONLY,
   not the composite Hash_cfg chain. Fix this gap:
   - Drive the full chain (not just SHA-256) with 10,000 distinct
     (SEED, NONCE, request) triples over 1 hour of simulated load.
   - Collect output bytes into a 256-bin histogram (320,000 total
     observations / 256 bins = 1250 expected per bin).
   - Compute chi-square. Assert **p > 0.05** (the null hypothesis of
     uniform output is not rejected at 5% significance).

2. **Autocorrelation at lags 1, 2, 4, 8, 16, 32.** Compute Pearson
   correlation between proof output at step `n` and step `n+k` for
   `k ∈ {1, 2, 4, 8, 16, 32}`. Assert all correlations are within
   `± 3σ / sqrt(N)` of zero.

3. **Simulated seed compromise.** Capture `P_100` (chain at step 100).
   Given `P_100`, attempt to compute `P_99, P_98, ..., P_0` by any of:
   - Brute-force over the hash input space (bounded by nonce range).
   - Algebraic attack (is there a closed-form inverse of `H_cfg`?).
   - Assume `P_100` discloses the current `hash_cfg`, attempt to
     rewind based on cfg-derivation logic at
     `trust_ape.c:504`.
   Expect: all attacks fail to produce `P_{n-1}` in feasible time.

**Success criterion.** Strategies 1 and 2 pass; strategy 3 fails-to-
find (i.e., the attacks do not succeed).

**Counter comparison.** Unlike T1/T2/T4/T5/T6, T3 does not have a
runtime violation counter because it is statistical. Strategy 1's
p-value is the analog. A p < 0.05 outcome is the "violation";
our goal is to never see that.

**LOC estimate.** ~120.

**Note on research D §1.5.** The existing chi-square witness in
`trust_ape_markov.c` is marked as a lower-bound test: "if SHA-256
alone fails uniformity, the composite chain certainly does. A passing
SHA-256 test does NOT prove the composite is uniform." Strategy 1
above fixes this gap by driving the composite chain; this test is
therefore a strict extension of the existing module-load witness.

---

### §2.T4 — Bounded Authority Inheritance

**Theorem statement.** For mitotic spawn: `S_max(child) < S_max(parent)`
(strict). For meiotic combine: `S_max(shared) ≤ min(S_max(A), S_max(B))`.

**Counter:** `/sys/kernel/trust_invariants/theorem4_violations`.

**Adversary model.** Userspace process attempting to spawn a child
subject with authority greater than its parent's, OR meiotic combine
of two subjects A and B producing a shared subject with authority
greater than `min(S_A, S_B)`.

**Test strategies:**

1. **Direct mitotic escalation.** Create parent subject with
   `S_max = 100`. Attempt to spawn child with `S_max = 150`. Expect:
   spawn refused + counter increment + no child created (or child
   created with `S_max < 100`).

2. **Equal-score mitotic spawn.** Parent `S = 100`, child `S = 100`.
   Expect: refused (strict inequality, `S_child < S_parent` not
   `≤`).

3. **Meiotic super-combine.** A `S = 50`, B `S = 70`. Attempt shared
   with `S = 80`. Expect: refused + counter increment + shared clamped
   to `min(50, 70) = 50` OR creation refused entirely.

4. **Multi-generation cumulative escalation.** Parent `S = 100`,
   spawn 10 successive children each nominally with `S_i = S_{i-1}
   + 1` (by the adversary's claim). Each mitosis should refuse;
   counter should increment 10 times.

5. **Kernel-write attack on S field.** (Requires `CONFIG_DEBUG_
   TRUST_WRITE_TEST=y`.) Spawn child legitimately; kernel-write-
   overwrite child's `S_max` to parent's value + 10. Perform any
   action on child. Expect: chromosome CRC mismatch, immune system
   flags the subject suspicious, apoptosis triggered. (This is a
   secondary line of defense beyond T4's strict-inequality check.)

**Success criterion.** Strategies 1-4: refused + counter fires.
Strategy 5: suspicious + apoptosis (does not bump theorem4 counter
because the violation was not through the legitimate code path;
bumps immune-system counter instead).

**LOC estimate.** ~120.

---

### §2.T5 — Guaranteed Revocation O(1)

**Theorem statement.** Per-subject apoptosis latency is bounded by
10 µs (default in `trust_invariants.c:67`). The bound holds even
under cascade (revoking a subject with N descendants).

**Counter:** `/sys/kernel/trust_invariants/theorem5_violations` +
`/sys/kernel/trust_invariants/theorem5_max_us` (the running maximum).

**Adversary model.** Not adversarial in the "malicious actor" sense —
this is a performance / DoS-resistance assertion. The "adversary" is
**load**: how much cascade does it take before per-subject latency
exceeds 10 µs?

**Test strategies:**

1. **Single-subject revoke.** Create one subject, measure
   `trust_lifecycle_apoptosis()` from start to end. Assert
   `< 10,000 ns`. Assert `theorem5_max_us` is updated.

2. **Cascade of 10.** Subject with 10 children. Trigger parent
   apoptosis. Measure per-child apoptosis latency. Each must be
   `< 10,000 ns`; aggregate may be larger but invariant is
   *per-subject*, not *per-cascade*.

3. **Cascade of 100.** Same as strategy 2 with 100 children. Stress
   tests slab allocator, spinlock contention, RCU-free paths.

4. **Concurrent apoptosis.** 10 threads, each revoking 10 different
   subjects simultaneously. Per-subject latency must still hold.

5. **Under memory pressure.** Allocate slab memory until nearly full;
   trigger apoptosis. Does the slab-free path in apoptosis slow down
   under memory pressure?

**Success criterion.** `theorem5_max_us < 10000` across all
strategies. If any scenario exceeds, the `theorem5_violations`
counter increments.

**LOC estimate.** ~100.

---

### §2.T6 — Metabolic Fairness

**Theorem statement.** Per-action token budget (TRC cost_multiplier
in 8.8 fixed-point) prevents a single subject from monopolising any
action class. No subject can starve other subjects of the shared
token pool.

**Counter:** `/sys/kernel/trust_invariants/theorem6_violations` (via
the bridge macro `TRUST_THEOREM6_VIOLATE(reason)` at
`trust/include/trust_theorems.h:148-149`, incremented from
`trust_authz.c`).

**Adversary model.** A single subject executing a tight loop of
high-cost actions, attempting to starve other subjects.

**Test strategies:**

1. **Single-subject burn.** Subject A in tight loop calling
   TRUST_ACTION_FILE_OPEN. Subject B attempting one
   TRUST_ACTION_FILE_OPEN every 100ms. Expect: B's calls succeed
   despite A's monopolisation; at some point A is throttled (token
   balance hits zero, TRC rejects). Counter increments if A's
   burn-rate exceeds the fairness threshold.

2. **Multi-subject burn.** 10 subjects in tight loop. Aggregate
   system throughput should not collapse.

3. **Asymmetric cost multiplier.** Subject A with
   `cost_multiplier = 0` (trivial rejection expected — cost must be
   positive). Subject B with `cost_multiplier = 255` (very
   expensive). B should exhaust tokens quickly; A should be
   immediately rejected.

4. **Token overflow.** Subject with token balance at u64 max;
   attempt another burn. Expect: saturation, not overflow; counter
   fires if saturation is handled incorrectly.

5. **Shared-pool starvation.** Research E §5.3 notes T6 could be
   stated without biology framing — it's a fairness invariant on
   resource allocation, equivalent to Linux CFS per-cgroup fairness.
   Test that two subjects with equal `cost_multiplier = 256` (1.0x)
   get equal action-throughput under contention.

**Success criterion.** Counter fires when a violation is detected;
fairness is preserved under load.

**LOC estimate.** ~100.

---

### §2.T7 — Statistical Anomaly Detection

**Theorem statement.** A statistical witness (chi-square over Markov
transition probabilities) detects anomalous authority-transition
patterns.

**Counter:** No dedicated T7 counter. The witness is statistical; its
"violation" is a failed chi-square test on injected adversarial
patterns.

**Adversary model.** A subject whose action pattern deviates from
typical Markov behaviour — e.g. repeatedly alternating between
actions that should be unrelated, creating impossible authority
transitions.

**Test strategies:**

1. **Legitimate baseline.** Run 10 subjects with realistic workload
   for 1 hour. Capture the Markov transition-probability matrix.
   Confirm witness `p > 0.05` for legitimate behaviour.

2. **Injected impossible transitions.** One subject deliberately
   performs transitions that violate the learned Markov model.
   Expect: within N ticks, the statistical witness flags the subject
   as anomalous.

3. **Low-rate anomaly.** Adversarial subject inserts one bad
   transition every 100 legitimate ones. Test that even a diluted
   anomaly is detected (may require longer window).

4. **Adversarial retraining attack.** Attacker gradually shifts
   Markov behaviour toward their malicious pattern (gradient of
   transitions over 1 hour). Test that the witness detects drift
   faster than the attacker can shift.

**Success criterion.** Strategy 1 passes (no false positive on
legitimate load); strategies 2-4 are flagged (true positive on
injected anomaly) within bounded time.

**LOC estimate.** ~110.

---

## §3. LOC summary + effort estimate

| Component | LOC |
|-----------|-----|
| `scripts/test-roa-theorems.sh` | 30 |
| `tests/adversarial/README.md` | (doc, N/A) |
| `tests/adversarial/conftest.py` + fixtures | 60 |
| `tests/adversarial/harness/counters.py` | 40 |
| `tests/adversarial/harness/subject_factory.py` | 60 |
| `tests/adversarial/harness/proof_replay.py` | 80 |
| `tests/adversarial/harness/kprobe_tap.py` | 60 |
| `tests/adversarial/harness/entropy_sampler.py` | 50 |
| `tests/adversarial/kernel_shim/test_shim.c` | 180 |
| `tests/adversarial/theorem_violation_suite.py` | — |
| — T1 strategies | 150 |
| — T2 strategies | 100 |
| — T3 strategies (no counter; stats instead) | 120 |
| — T4 strategies | 120 |
| — T5 strategies | 100 |
| — T6 strategies | 100 |
| — T7 strategies | 110 |
| **Total** | **~1360 LOC** |

Per research J §5 Proposal A the original estimate was ~800 LOC. This
document expands to ~1360 LOC to include the three per-test
expansions from the research reports (T1 with 5 strategies, T3 with
the composite-chain chi-square gap fix per D §1.5, T4 with the
multi-generation cumulative + kernel-write sub-tests). An agent with
a narrower scope could ship the core ~800 LOC (2-3 strategies per
theorem) in one session; the full ~1360 LOC is 1-2 sessions.

**Effort per research J**: *"Per research-J this is the highest-ROI
single move on the S75 roadmap."*

---

## §4. Attack classes covered vs. not covered

### Covered

| Adversary class | Covered strategies |
|-----------------|---------------------|
| **Userspace attacker without root** | T1 strategies 1-4; T2 strategies 1-3, 5; T4 strategy 1-4; T7 strategies 2-4 |
| **Userspace attacker with CAP_SYS_ADMIN** | All userspace strategies + T1 strategies 3 (`/proc/kcore`) and 5 (BPF tracer) |
| **Replay attacker (message-replay)** | T2 all strategies |
| **Resource-starvation attacker (DoS)** | T5 strategies 2-5, T6 strategies 1-2 |
| **Statistical anomaly** | T3 strategies 1-2, T7 all strategies |

### NOT covered

| Adversary class | Why not covered | Notes |
|-----------------|-----------------|-------|
| **Kernel-resident attacker (rootkit)** | The harness deliberately avoids testing against a kernel-resident adversary because (a) at that level, `trust.ko` is fundamentally indefensible (kernel is the TCB); (b) the relevant mitigations are orthogonal (I-8 `__ro_after_init`, S72 TPM2 attestation, I-7 self-attestation). | Research D §1.4 explicitly documents this: "APE is designed to defend against misbehaving but non-root userspace subjects who hold a trust_subject_id. It is not designed to defend against a peer kernel resident." Tests that REQUIRE kernel-write (T2 strategy 4, T4 strategy 5) are gated behind `CONFIG_DEBUG_TRUST_WRITE_TEST=y` and are explicit QA-only tests. |
| **Hardware-fault attacker (rowhammer, cosmic-ray)** | Out of scope. Research G §1 notes the quorum protects against uncorrelated transient faults; a harness for this would need a rowhammer framework (not trivially reproducible on all systems). | Recommend: separate fault-injection harness in S76+, using `memtest86`-style tools. |
| **Supply-chain attacker (malicious build)** | Orthogonal. Mitigation is bootc + MOK signing + PCR-11 attestation (S72). This harness does not test the build pipeline. | Research J §3.3 flags "FPGA-validated hardware substrate" as aspirational; supply-chain is the complementary axis. |
| **Side-channel attacker (Spectre, MDS)** | Requires specialised microarchitectural tools. Research D §1.4 notes residual vectors; not in this harness. | Recommend: defer to upstream mainline mitigations (IBPB, SSBD, RETPOLINE) + specific APE cache hardening per I-2 strengthening (CLFLUSH). |
| **Cryptographic attacker (SHA-256 break)** | Out of scope. If SHA-256 falls, every APE proof falls; no test harness compensates. | The hash reconfigurability per research D §0.3 gives some post-break defense; but if all 3 (or all 94M claimed) hash configs fall, the system is done. |

### Summary

The harness exercises the **non-kernel-resident, non-hardware-fault**
adversary classes exhaustively. Kernel-resident and hardware-fault
adversaries are defended by orthogonal mechanisms (I-7 self-
attestation, I-8 dispatch-table RO, S72 TPM2 attestation, upstream
microarchitectural mitigations) — not by this harness.

---

## §5. Interoperation with research G's quorum threat-model table

Research G §0 classifies the `trust_quorum_vote` primitive:

> trust_quorum_vote() is **not** Byzantine fault tolerant. It is a
> deterministic integrity check — a chi-square-style witness that the
> 23 chromosomal pairs collectively agree on a pseudo-independent
> 1-bit opinion about a given field.

This harness's quorum-related tests (primarily under T4 strategy 5
and T7 strategy 2) exercise the primitive against the adversary
classes it *is* designed to defend against, not ones it isn't.

### Quorum level ↔ adversary class mapping

| Quorum level | Mechanism | Adversary defended | Harness test |
|--------------|-----------|---------------------|--------------|
| **L0 (current)** | Per-pair deterministic opinion bit, 16/23 threshold | Crash / bit-flip / silent memory corruption / cosmic-ray | T7 strategy 1 (baseline uniform) shows no false positives under clean load |
| **L1 (future, research G §6)** | Add HMAC-SHA-256 over the vote vector, kernel-secret-keyed | Userspace tamper (the kernel-secret is unreachable from userspace) | (Would add: verify tampered vote vector is rejected) |
| **L2 (future, research G §6)** | Replace HMAC with Ed25519 per-pair signatures, pair-specific keys | Compromise of one pair's key doesn't compromise the whole vote | (Would add: simulate key compromise, verify 22/23 remain trustworthy) |
| **L3 (future, research G §6)** | BLS threshold signatures, 16-of-23 reconstructs | Byzantine adversary controlling up to 7 pairs | (Would add: simulate Byzantine tampering of 7 pairs; verify vote survives) |

**Current test harness exercises L0 only.** Upgrading to L1/L2/L3 is
an S75+ code change (~500 LOC per research G §6), with corresponding
harness additions (each level adds ~100 LOC of tests).

---

## §6. Integration with CI

Once implemented, the harness runs:

- **Pre-merge:** every PR that touches `trust/kernel/*.c`, `trust/
  include/*.h`, or `tests/adversarial/*`. Target: complete in < 5
  minutes on a single CI runner.
- **Nightly:** extended harness with 1-hour T3 chi-square / T7 drift
  tests. Target: complete in < 2 hours.
- **Release gate:** all harness tests must pass on the pre-tagged
  build. Failure blocks release.

Wired into `.github/workflows/` via:

```yaml
# .github/workflows/theorem-violation.yml (proposed)
name: Adversarial Theorem Harness
on: [pull_request, schedule]
jobs:
  adversarial:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build trust.ko
        run: make -C trust/kernel
      - name: Run harness (short)
        if: github.event_name == 'pull_request'
        run: ./scripts/test-roa-theorems.sh --short
      - name: Run harness (full)
        if: github.event_name == 'schedule'
        run: ./scripts/test-roa-theorems.sh --full
```

---

## §7. What this harness does NOT do

To keep the scope honest:

- **Does not prove the theorems.** It demonstrates them under
  specific adversary behaviours. A formal proof (Coq/Isabelle) is
  orthogonal, PhD-sized, and out of scope — research I §0.1 covers
  the effort estimate.
- **Does not cover T3/T7 as completely as T1/T2/T4/T5/T6.**
  Statistical theorems are harder to "violate on demand"; the tests
  attempt anomalous patterns but cannot exhaustively explore the
  adversarial input space.
- **Does not test the paper's 94M-config reconfigurable hash claim.**
  Per architecture-v2.md Finding #10 / paper-vs-implementation.md
  §1 entry 4, code ships 3 hash configs, not 94M. Until that
  regression is triaged (S74 Agent 10 Task 5), the harness tests the
  3-config reality.
- **Does not test cross-substrate equivalence.** The FPGA POC ↔
  x86_64 bisimulation harness is a separate document / effort
  (~680 LOC per research I §4, S75+).
- **Does not test the algedonic channel.** That's a separate
  integration test under S74 Agent 10's `algedonic_reader.py`.

---

## §8. Recommendation to S75 agent

When implementing this harness:

1. **Start with T2 and T4.** Both have clear sysfs counters and
   simple violation strategies. Quick wins.
2. **T1 comes next.** Walk sysfs/debugfs surfaces is mechanical. The
   BPF-tracer strategy (T1-5) requires more setup but is the most
   valuable; skip-skip-land if time is tight.
3. **T3 is the research-heavy one.** Per research D §1.5 the existing
   SHA-256-only witness is caveated as lower-bound; strategy 1's
   composite-chain chi-square is the intended fix. Budget extra
   time.
4. **T5 is performance testing, not adversary testing.** Can be
   deferred if load comes from another source (stress test suite).
5. **T6 is coupled to TRC cost_multiplier semantics.** Read
   `trust_authz.c` thoroughly first; T6 strategies 3-5 are easy to
   get wrong if you don't understand the 8.8 fixed-point cost
   semantics.
6. **T7 is the statistical one.** Interacts with `trust_ape_markov.c`;
   budget reading time.

**Agent brief template** (for S75):

```
S75 agent N — adversarial theorem harness

Scope: implement tests/adversarial/ per docs/runtime-theorem-
validation.md. Target 1360 LOC across the 7 test classes + harness
helpers + kernel shim. Land CI wiring at .github/workflows/
theorem-violation.yml.

Phased delivery:
  Phase 1 (2-3 hrs): T2 + T4 (core security theorems, simplest
                      counter-comparison pattern)
  Phase 2 (2-3 hrs): T1 + T5 + T6 (remaining counter-based tests)
  Phase 3 (2-3 hrs): T3 + T7 (statistical tests, harder)
  Phase 4 (1 hr):    CI wiring + documentation

Acceptance criteria:
  - Every theorem has ≥ 2 violation-attempt tests
  - Counters snapshot/diff pattern is consistent across all tests
  - No harness test requires kernel-write unless explicitly gated
    behind CONFIG_DEBUG_TRUST_WRITE_TEST=y
  - CI job runs in < 5 min for pre-merge; < 2 hr for nightly
  - Each test class has a class docstring citing the paper section +
    this document's §2.Tx

Non-goals:
  - Formal proof (not in scope; research I task)
  - Cross-substrate bisim (separate effort per research I §4)
  - 94M-config hash test (blocked on architecture-v2 Finding #10)
  - Algedonic integration (S74 Agent 10)
```

---

**End of runtime-theorem-validation.md.**
