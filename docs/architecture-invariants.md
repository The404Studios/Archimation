# Architecture Invariants — ARCHWINDOWS / Root-of-Authority

**Document purpose.** Formalise the architectural invariants that make
this specifically an **architecture** (as opposed to a pile of features)
per Research F §1's Turing-incompleteness argument and the synthesizer's
architecture-v2.md §6.

**An architecture is not a list of features. It is a list of invariants
that every feature must preserve.**

**Status.** S74 research deliverable, Agent L. Companion to
`docs/architecture-v2.md`.

**Source research reports.** F (`s74_f_homoiconic_isa.md`), D
(`s74_d_crypto_audit.md`), G (`s74_g_reliability_consensus.md`), H
(`s74_h_observation_primitives.md`), C (`s74_c_endosymbiosis.md`), J
(`s74_j_moat_landscape.md`), E (`s74_e_chromosomal_model.md`),
strategic memo (`roa_paper_validation_tier_audit_and_s74_plan.md`).

**Each invariant below has.**
- **Statement** — the property.
- **Rationale** — why it is an invariant (what collapses without it).
- **Enforcement** — runtime-check, build-time-check, or documented-only.
- **Verification procedure** — how a reviewer confirms it holds.
- **Known violations** — current gaps, citing research.

---

## §1. I-1: Turing-incompleteness of the trust ISA (no self-emission)

**Statement.** No trust-ISA handler may emit a trust instruction to a
queue for later execution by the kernel. The instruction stream is
strictly userspace-to-kernel one-way, per-call bounded, with:

- **No unconditional jumps** — predicate bit permits stride ≤ 63,
  **backward-only** (per `trust/include/trust_isa.h:247-259`; see
  research F §0).
- **No unbounded loops** — `TRUST_CMD_MAX_BATCH = 256` (one instruction
  per batch slot; hard cap checked in `trust_dispatch.c` batch reader).
- **No indirect dispatch** — `dispatch_table[family][opcode]` is a
  static array indexed by encoded instruction fields; no runtime
  pointer lookup beyond this.
- **No arbitrary memory reads** — handlers receive pre-decoded operands;
  they do not dereference raw userspace pointers at dispatch time.
- **No self-emission** — no handler in `trust/kernel/trust_*.c` calls
  `trust_isa_enqueue_for_self` or equivalent.

Every batch terminates in bounded steps. Every authorization decision
is decidable in bounded time.

**Rationale.** This is the moat against policy-language explosion.
Research F §1 is the argument in full: if `trust.ko` could `eval` an
instruction that it itself emitted, the set of authorizations a subject
can eventually gain becomes undecidable (Rice's theorem). The value
proposition of the trust-ISA is that *given a batch buffer and a
subject's current capability set, we can answer in bounded time "will
this batch ever allow action X?"* — this is why every handler in
`trust_dispatch.c` is `O(1)` or `O(|cap mask|)` and there's no
general-recursion opcode.

Every other invariant in this document depends on this one: if policy
is Turing-complete, none of T4 / T5 / T6 is statically analyzable.

**Enforcement today.** Eyeball only. `grep -r 'trust_isa_enqueue\|
trust_cmd_enqueue\|trust_dispatch_self' trust/kernel/` returns no
matches, so the invariant holds at this HEAD by absence. There is
**no build-time check** preventing a future handler from adding one.

**Verification procedure.**

1. Grep the kernel tree for symbols matching any enqueue-for-self
   pattern:
   ```
   grep -rn 'trust_.*_enqueue\|self_emit\|dispatch_reenter' trust/kernel/
   ```
   Expected: zero matches.
2. For each of the 6 canonical families (AUTH/TRUST/GATE/RES/LIFE/META)
   + 2 auxiliary (VEC/FUSED), read the handler table at
   `trust_dispatch.c:1293-<end-of-table>` and confirm no handler opens
   a writable cursor into a global instruction queue.
3. Static analysis (cppcheck, coverity, sparse): confirm no handler
   takes an `instruction_word *` argument that is mutated. All
   handlers should operate on already-decoded operands.

**Proposed strengthening (~60 LOC, S75+).** Runtime assertion in
`trust_invariants.c`: every handler's stack frame must not have called
any function whose symbol matches `trust_isa_enqueue_*` or
`trust_dispatch_*_reenter`. Weak (bypassable by indirect call through
function pointer) but visible in `ftrace`.

**Stronger strengthening (~120 LOC, S76+).** Build-time proof via a
static-analysis pass: enumerate all handlers, verify none takes an
`instruction_word*` argument. Per research F §7. This moves the
check from runtime to build time — the CI fails if anyone adds a
homoiconic handler. This is the preferred long-term enforcement.

**Known violations.** None at HEAD `071b6aa`. But research F §0
flags a related concern: **`dispatch_table` itself is NOT
`__ro_after_init`** (see I-8 below). A kernel-write adversary could
flip handler pointers and effectively create a homoiconic handler
post-hoc. I-1 and I-8 are therefore coupled.

---

## §2. I-2: Destroy-on-read for APE proofs

**Statement.** `trust_ape_consume_proof` atomically reads the proof
register `Pn` and writes zeros back to the 32-byte field, under the
per-entry spinlock, before any further code observes `Pn` outside the
locked region. A proof may be read at most once.

**Rationale.** This is the core security primitive of the Authority
Proof Engine. Without destroy-on-read, a compromised subject could
replay a single proof indefinitely, defeating T2 (Non-Replayability).
Research D §1.1 and A §2.5 identify this as **structurally identical
to Von Neumann 1932 Process 1 measurement collapse** — the observation
destroys the observed state; the next state derives from what was
observed. This framing unlocks no-cloning (Wootters-Zurek 1982) and
no-broadcasting (Barnum et al. 1996) as security theorems. See
paper-vs-implementation.md §2.T-ape-processone.

**Enforcement today.** Runtime-enforced by code at `trust_ape.c:486-
488`:

```c
memcpy(consumed_proof, entry->state.proof, TRUST_PROOF_SIZE);
memzero_explicit(entry->state.proof, TRUST_PROOF_SIZE);
entry->state.proof_valid = 0;
```

`memzero_explicit` is the kernel API the compiler is **forbidden** from
optimising away (contrast `memset`, which can be). See
`include/linux/string.h` and `lib/string.c` in mainline Linux. The
zeroization + `proof_valid = 0` flag + per-entry spinlock +
write-before-unlock sequence together implement the invariant.

**Verification procedure.**

1. Read `trust_ape.c:486-488`. Confirm `memzero_explicit` is called on
   the `proof` field after the copy.
2. Read `trust_ape.c:484-500`. Confirm the whole sequence runs under
   `entry->lock` (taken at :483, dropped post-zeroing).
3. Unit test: `tests/unit/test_ape_consume.c` (exists in tree) — call
   `trust_ape_consume_proof` twice back-to-back on the same subject;
   second call must return an error (no valid proof to consume).
4. Strong-bisim test (research I §2.2): feed identical (seed, request,
   nonce) to both the code and a hand-computed reference; assert
   outputs match. The read-and-zero is externally visible as "second
   read fails."

**Known concerns (not strict violations, but defense-in-depth gaps).**
Per research D §1.2 and §3.3:

- **L1/L2/L3 cache retention.** `memzero_explicit` does not issue
  `CLFLUSH` / `CLFLUSHOPT`. The zeroed value survives in dcache until
  naturally evicted. A speculative side-channel attacker (Spectre-v2,
  L1TF, MDS) could potentially recover during a short window. **Fix
  (~5 LOC):** add `clflushopt(&entry->state.proof)` after zeroing.
- **Register file.** CPU registers that held partial SHA state are not
  explicitly clobbered; depends on compiler register allocation. **Fix
  (~5 LOC):** `asm volatile("" ::: "memory")` barrier after
  `compute_proof` returns.
- **Hibernation image.** `g_trust_ape.entries[]` is in kernel .bss /
  slab. Not marked `__nosave`, not `mlock`'d. On hibernation, past
  proofs may be written to swap. **Fix (~3 LOC):** `__nosave` on the
  array declaration.

None of these invalidates I-2 *as stated* (the field-overwrite is
rigorous); they extend the threat model beyond what the invariant
currently defends.

---

## §3. I-3: Monotonic authority decay / bounded authority inheritance

**Statement.** For any subject transitioning under the lifecycle:

- **Mitotic spawn:** `S_max(child) < S_max(parent)`.
- **Meiotic combine:** `S_max(shared) ≤ min(S_max(A), S_max(B))`.

Both are strict inequalities for the mitotic case (child authority
strictly less than parent); the meiotic case is `≤` to allow the
degenerate case of two identically-scored parents.

**Rationale.** This is **Theorem 4** in the paper (Roberts/Eli/Leelee,
Zenodo 18710335, §Security Theorems). Per research E §5.1, it maps
cleanly onto the **Hayflick limit** in biology — telomere shortening
per mitotic division (~50-70 bp/division, ~50 divisions before
senescence). The invariant is the moat against privilege escalation
via fork: a subject cannot acquire authority it did not inherit from
somewhere above; authority can only decay, never amplify.

Without I-3, a fork-bomb escalates to a denial-of-service or, worse, a
privilege-escalation: a low-trust subject spawns many children and
selects the child with the (random) highest score to advance its own
ambitions. I-3 prevents this by making `S_child < S_parent` structural.

**Enforcement today.** Runtime-enforced. Per
`trust/include/trust_theorems.h:82-103`:

- `trust_invariants_check_mitosis(parent, child)` — asserts
  `S_max(child) < S_max(parent)`. Bumps
  `/sys/kernel/trust_invariants/theorem4_violations` and
  `WARN_ON_ONCE` on violation.
- `trust_invariants_check_meiosis(A, B, shared)` — asserts
  `S_max(shared) ≤ min(S_max(A), S_max(B))`. Same counter, same
  WARN.

Called from `trust/kernel/trust_lifecycle.c` (mitotic spawn) and
`trust/kernel/trust_meiosis.c` (meiotic combine).

**Verification procedure.**

1. Read `trust_invariants.c` for the sysfs counter wiring. Confirm
   `theorem4_violations` is monotonic.
2. Read `trust_lifecycle.c` `_mitotic_parent_cb` — confirm the
   `trust_invariants_check_mitosis` call is on every spawn path.
3. Read `trust_meiosis.c:237-448` — confirm the
   `trust_invariants_check_meiosis` call is present.
4. **Adversarial test** (per `docs/runtime-theorem-validation.md` §2
   T4): deliberately spawn a child with `S_child ≥ S_parent` and
   verify (a) child creation is refused / aborted, (b) counter fires.
   This test does not currently exist — counter has never been seen
   non-zero under clean load (research J §3.3).

**Known violations.** None structurally. The **runtime** verification
gap (counter never observed non-zero) is T-runtime in paper-vs-
implementation.md §2.

---

## §4. I-4: Cortex-veto-only

**Statement.** The AI cortex (Layer 4, `ai-control/cortex/*`) may
**reject** a proposed action but may not **originate** one. The cortex
is a subscriber to the event bus and an emitter of veto decisions to
the decision engine; it is never an authority originator.

**Rationale.** Per CLAUDE.md, `docs/architecture.md:§3`, and the
architecture-v2 §1 Layer-4 section. Rationale: an LLM-driven cortex is
an adversarial attack surface (prompt injection, hallucination, drift).
Its safest role is **counsel**: watch, flag, veto — never grant. A
compromised cortex that could originate authority would be a one-stop
privilege escalation.

**Enforcement today.** Eyeball + pipeline order only.

Per research J §3.3: *"a malicious cortex could call `trust_action` as
easily as `trust_veto`."* No typestate check, no separate
`/dev/trust_cortex` device, no kernel-side capability bit prevents
origination. The invariant is a convention, not a mechanical
guarantee.

**Verification procedure.**

1. Grep cortex for any path that emits an authority GRANT as opposed
   to a DENY/VETO:

   ```
   grep -rn 'grant\|GRANT\|originate\|ORIGINATE\|trust_action' ai-control/cortex/
   ```

   At time of this document's preparation, this returns:
   - `ai-control/cortex/event_bus.py:116` — comment "Cortex-originated
     events" (events, not authority grants; benign)
   - `ai-control/cortex/decision_engine.py:499` — comment mentioning
     "originate from" (memory maps, benign)

   Three files reference `trust_action|TRUST_ACTION|/dev/trust`:
   `orchestrator.py`, `config.py`, `trust_translate.py`. **None has
   been audited** for veto-only discipline. Audit required.

2. Audit `ai-control/cortex/decision_engine.py` pipeline order: policy
   → heuristic → LLM. Confirm LLM output cannot promote a deny to an
   allow without passing through a separate authority-originating
   kernel call.

3. Audit `ai-control/cortex/autonomy.py:32-43` — autonomy-level gate.
   Confirm below SOVEREIGN the cortex cannot self-modify.

**Proposed strengthening (~80 LOC, S75).** Two-level:

- **Python-side typestate:** decorate veto-only cortex methods with
  `@veto_only`; decorate any `trust_action`-calling helper as
  `@requires_capability(Capability.ORIGINATE)` which the cortex does
  not hold. Add runtime check. ~60 LOC.

- **Kernel-side separate device:** create `/dev/trust_cortex` that
  accepts only veto operations (`TRUST_IOC_VETO`). Cortex opens
  `/dev/trust_cortex` (not `/dev/trust`); kernel refuses origination
  ops on this fd. ~20 LOC + udev rules.

With both in place, I-4 becomes mechanically enforced.

**Known violations.** Convention-only at HEAD. No known malicious-
cortex code path has been exploited, but the guarantee is not
defensible without strengthening.

---

## §5. I-5: Kernel never calls upward

**Statement.** Layer 0 (`trust/kernel/*`, i.e. `trust.ko` and its
`wdm_host.ko` companion) makes no calls to Layer 1 (pe-objectd),
Layer 2 (pe-loader + DLL stubs), Layer 3 (scm-daemon), or Layer 4
(ai-control cortex). Upward communication is only via:

- Event bus publications (fire-and-forget, no response semantics).
- Algedonic-channel emissions (`/dev/trust_algedonic` miscdevice —
  kernel writes, userspace reads).
- Sysfs counters (pull-only; userspace polls).

The kernel has no RPC, no socket-open, no usermodehelper call upward.

**Rationale.** Per CLAUDE.md and `docs/architecture.md:§1`:
*"Commands flow down, events flow up. No layer calls upward."* This
is the **unidirectionality invariant** of the layered architecture.
Without it, circular dependencies emerge (kernel depends on daemon
depends on kernel) and boot-order determinism breaks. More critically,
a kernel that calls upward can be blocked by unresponsive userspace —
a trivial DoS vector.

**Enforcement today.** Eyeball only. Verification by grep:

```
grep -rn 'call_usermodehelper\|socket.*AF_UNIX\|connect(' trust/kernel/
```

At HEAD `071b6aa`, this returns no matches for upward-RPC patterns.
`trust_algedonic.c:193` creates a `miscdevice` with mode 0440 (kernel-
created, userspace-reads); this is downward emission of data, not an
upward call. The invariant holds.

`pr_info`, `pr_warn`, `pr_err` to the kernel log are not upward calls
(they write to the kernel log buffer which userspace later reads; no
synchronous wait).

**Verification procedure.**

1. Grep kernel tree for any of:
   - `call_usermodehelper` / `call_usermodehelper_exec`
   - `sock_create(AF_UNIX, ...)`, `kernel_connect(...)`
   - `UMH_*` (usermodehelper constants)
   - `request_module` (benign — kernel-side; but flag for review)
   - `netlink_unicast` / `netlink_kernel_create` (benign if only
     downward-notify; flag if kernel waits for response)
2. Read `trust_algedonic.c` fully (294 LOC). Confirm the miscdevice
   supports `read()` from userspace only; kernel never synchronously
   waits for a reader.
3. Read `trust_core.c` module init path. Confirm `trust_init` does not
   spawn usermodehelper.

**Proposed strengthening (build-time, ~10 LOC).** Add a CI lint:

```yaml
# .github/workflows/no-upward-calls.yml
- grep -rn 'call_usermodehelper\|kernel_connect\|UMH_' trust/kernel/ && exit 1 || exit 0
```

Fails CI if anyone adds an upward-call primitive.

**Known violations.** None at HEAD. The invariant is clean.

---

## §6. I-6: Every producer must have a consumer (S74 anti-pattern codification)

**Statement.** Any event channel, counter, device file, ISA opcode,
syscall, or published signal **must name at least one in-tree
consumer** at the time it is merged, OR be feature-flagged off until
such consumer exists.

**Rationale.** Per architecture-v2.md §4 Finding #6 — the convergent
finding from research C §0 and H §1.5. **Four current violations** at
HEAD (listed in "Known violations" below). A producer-without-consumer
channel is either:

- **Dead data** — kernel cycles emitting signals no one reads
  (autopoietic closure broken per Maturana-Varela; VSM algedonic
  principle defeated per Beer).
- **Future attack surface** — signals a future attacker may learn to
  manipulate before any legitimate consumer exists.
- **Silent regression** — the consumer *used to exist* and was deleted,
  leaving the producer orphaned. Research D §0.3 / architecture-v2
  Finding #10 suggests this may be the case for APE's `consume_proof_v2`.

This invariant is the one we are codifying **now** so future PRs cannot
add more producer-without-consumer channels.

**Enforcement today.** Does not exist as a gate. This invariant is a
NEW proposal from S74 Agent L (this document).

**Verification procedure.**

1. For every new event-type `#define` in `pe-loader/include/eventbus/
   pe_event.h`:
   ```
   grep -rn 'pe_event_emit(<TYPE>' pe-loader/
   ```
   Must return ≥1 match (the emit site).
   ```
   grep -rn 'case <TYPE>:\|if.*type == <TYPE>' ai-control/ pe-loader/
   ```
   Must return ≥1 match (the consume site).
2. For every new sysfs counter: grep for the `show()` function AND at
   least one consumer (test harness, observer, or documented operator
   dashboard).
3. For every new ISA opcode: confirm there is a decode path AND at
   least one handler OR an explicit feature-flag `#ifdef` that keeps
   the opcode un-dispatched until a handler exists.

**Proposed strengthening (~40 LOC, S75).** PR-template checklist:

```markdown
## Producer/Consumer checklist (I-6)

For every new:
- [ ] `pe_event_emit` site → name the `ai-control/` or
      `pe-loader/` consumer file:line
- [ ] Algedonic reason code → name the userspace reader
- [ ] Sysfs counter → name the operator dashboard / test that reads it
- [ ] ISA opcode → name the handler (or feature-flag)
- [ ] `/dev/` file → name the userspace program that opens it

If consumer is future, mark with `#ifdef FEATURE_FOO` + `CONFIG_FOO=n`
by default.
```

Plus CI grep that flags any `#define PE_EVT_*` without a matching
`pe_event_emit(PE_EVT_*` in the same tree AND a matching consumer.

**Known violations at HEAD `071b6aa`.** Per architecture-v2.md Finding
#1, C §0.2, H §1.5:

1. **`/dev/trust_algedonic`** — kernel emits at
   `trust/kernel/trust_algedonic.c:253`; no userspace reader. (Being
   fixed by S74 Agent 10's `ai-control/daemon/algedonic_reader.py`.)
2. **`PE_EVT_EXCEPTION`** — declared at `pe-loader/include/eventbus/
   pe_event.h:47`; `grep pe_event_emit(PE_EVT_EXCEPTION` returns **zero
   matches** across all of pe-loader. Producer absent as well as
   consumer; the event code is dead. Fix per research C §0.2 item 3
   (~40 LOC in `pe-loader/dlls/kernel32/kernel32_seh.c` + any VEH path).
3. **Mitokine channels (FGF21/GDF15-equivalent)** — proposed by
   research C §0 item 2; currently absent entirely (no declaration, no
   emit, no consumer). The most load-bearing retrograde-signalling
   gap.
4. **PE subsystem-aggregate stress event** — per C §0 item 2; no
   `PE_EVT_SUBSYSTEM_STRESS` exists in `pe_event.h`. Cortex cannot
   observe per-tier stress rollups; only per-process events.

All four will be tracked in PR tooling once I-6 is codified.

---

## §7. I-7: Self-attestation (aspirational)

**Statement.** Every APE proof computation must include
`SHA-256(trust.ko .text)` as a context term, so any tampering with the
kernel module's code segment invalidates all subsequent proofs.

**Rationale.** Per research F hint, architecture-v2.md §9 Proposal C,
and the S73 Cluster-4 meta-exploit (F self-attestation) flagged as
orthogonal-but-valuable. The self-attestation quine closes a hole in
the moat: currently, a kernel-write adversary that replaces a
`trust_*` function with a malicious one does not affect proof-chain
integrity (because proof computation does not touch the kernel's own
code). With I-7, the adversary's tampering would be reflected in the
`SHA-256(trust.ko .text)` term and all subsequent proofs would diverge
from what any legitimate verifier expects.

**Enforcement today.** **Not implemented.** Aspirational. Research
F §3 and S73 memory file note the concept; no code ships.

**Verification procedure (when implemented).**

1. Read proposed `trust_ape_verify_self()` in `trust_ape.c`: confirm
   it computes `SHA-256` over `_text_start..._text_end` and folds the
   result into the proof input alongside SEED / NONCE / TS / Rn / Sn.
2. Tampering test: `kprobe_register` that overwrites the first byte
   of any `trust_*` function; consume a proof; verify the proof
   output differs from a clean-kernel baseline.

**Proposed strengthening (~300 LOC, S75+).** Per S73 memory file and
architecture-v2.md §9 Proposal C:

- `trust_ape_verify_self()` at `trust_ape.c:<new>` computes SHA-256
  over kernel-text symbols.
- Called from `trust_ape_consume_proof` as a context input.
- Kernel text symbols (`_stext`, `_etext`, or module-local equivalents
  `__start_text`, `__end_text`) must be marked exported so the hash
  covers exactly the code segment, not data or BSS.
- Consideration: TPM2 PCR-11 already covers the module at load time
  (S72 γ `trust_attest.c`); I-7 adds runtime coverage, complementary
  not redundant.

**Known violations.** N/A — invariant is aspirational.

---

## §8. I-8: Dispatch table is `const __ro_after_init`

**Statement.** `trust_cmd_handler_t dispatch_table[FAMILIES][OPCODES]`
in `trust/kernel/trust_dispatch.c:1293` must be `static const
... __ro_after_init` — read-only after module init completes, mapped
into kernel rodata by `mark_rodata_ro()`.

**Rationale.** Per research F §0 and §7, architecture-v2.md §4
Finding #4, and architecture-v2.md §2.2 invariant. This is the W^X
hardening of the ISA dispatcher. Without `const __ro_after_init`, a
kernel-write primitive (CVE in any other LSM / driver / even
`trust.ko` itself) can flip a handler pointer and collapse the
authority graph: every subsequent `trust_dispatch_cmd_buffer` call
executes attacker-chosen code with kernel privilege.

I-8 and I-1 (Turing-incompleteness) are coupled: I-1 prohibits
self-emission via legitimate code paths; I-8 prohibits post-hoc
table mutation via illegitimate code paths (kernel-write CVE).
Together they make the dispatcher **structurally inviolable** under
a non-kernel-resident adversary model.

**Enforcement today.** **Currently violated** at
`trust/kernel/trust_dispatch.c:1293`:

```c
static trust_cmd_handler_t dispatch_table[TRUST_STAT_FAMILY_SLOTS][TRUST_CMD_MAX_OPCODES] = {
    /* rows... */
};
```

No `const`. No `__ro_after_init`. S74 Agent 10's Task 3 (see
`docs/agent10_integration_brief.md` §3) lands the fix in-session.

**Verification procedure.**

1. Read `trust_dispatch.c:1293`. Confirm declaration reads `static const
   trust_cmd_handler_t dispatch_table[...][...] __ro_after_init = {...}`.
2. Grep kernel tree for any assignment to `dispatch_table[x][y]`
   outside module init:
   ```
   grep -rn 'dispatch_table\[' trust/kernel/*.c
   ```
   Only writes should be at module init (struct-initialiser syntax);
   anything else is a violation.
3. Adversarial test (VM only — may cause OOPS): debug interface under
   `CONFIG_DEBUG_TRUST_WRITE_TEST` that attempts to write the table
   post-init. Must produce a page fault (not a silent write).

**Proposed strengthening.** Beyond `__ro_after_init`:

- `set_memory_ro((unsigned long)dispatch_table, pages)` after init,
  explicit — belt and suspenders for kernels where
  `__ro_after_init` is not fully wired. ~5 LOC.
- Struct Control Flow Integrity (CFI — `CONFIG_CFI_CLANG`): verify
  handler pointers match function-type hash. Kernel 6.x+ supports;
  landing this is a build-config change, not a source change.

**Known violations.** The primary violation is current and being
fixed. Once `const __ro_after_init` lands, I-8 is enforced.

---

## §9. I-9: Authority graph reachability (root-of-authority)

**Statement.** Every trust decision (every `trust_authz_check` return
value) must trace to a root-of-authority chain — a sequence of
(subject, parent, grandparent, ...) ending at either (a) the kernel
at module init, (b) a TPM2-PCR-11-anchored attestation (S72 γ), or
(c) an explicit admin-authorised root subject. No subject exists
outside such a chain.

**Rationale.** Per research G and J convergent observation. Without
I-9, "authority" is floating — a subject can claim authority without
showing provenance. This is the classic confused-deputy
vulnerability: if authority has no root, forging a subject with
arbitrary authority is just a kernel-write-primitive away.

With I-9 and I-3 (monotonic decay) together: every subject's
authority is bounded above by its parent's authority, which is
bounded above by its grandparent's, all the way up to the root; and
the root's authority is itself bounded by TPM2 attestation (I-7
strengthens this further).

**Enforcement today.** Partial. Per `trust_lifecycle.c`, every
subject has a `parent_id` field; `trust_subject_t.parent_id` must
either be a valid existing subject OR `TRUST_SUBJECT_ROOT_ID` (kernel-
issued root). Unit tests confirm.

**Verification procedure.**

1. Static: grep `trust_subject_t.parent_id` assignment sites. Each
   must either assign from an existing subject's ID or from the
   root-id constant.
2. Dynamic: walk all live subjects; for each, trace the parent chain
   upward. Every chain must terminate at the root.
3. Adversarial test (per `docs/runtime-theorem-validation.md` T4):
   attempt to create a subject with `parent_id = 0xDEADBEEF`
   (non-existent ID). Must refuse.

**Proposed strengthening (~60 LOC, S75+).** Periodic
`trust_authz_verify_reachability()` tick: once per second, walk the
subject pool and assert every subject reaches the root. Emit
algedonic alarm on any orphan (once the algedonic reader lands per
S74 Agent 10).

**Known violations.** None structural. Test coverage is thin; the
adversarial harness is the right next step.

---

## §10. Invariant dependency graph

| Depends on  | ← | Invariant |
|-------------|---|-----------|
| I-1 (Turing-incomplete) | → | all others (without I-1, nothing is statically analyzable) |
| I-8 (dispatch table RO) | → | I-1 (without I-8, runtime table-tampering reintroduces undecidability) |
| I-2 (destroy-on-read) | → | T2 Non-Replayability (paper theorem) |
| I-3 (monotonic decay) | → | T4 Bounded Authority Inheritance |
| I-4 (cortex-veto-only) | → | secure autonomy escalation story (cortex safety) |
| I-5 (no upward calls) | → | boot-order determinism + DoS resistance |
| I-6 (every producer has consumer) | → | closes autopoietic loop (Maturana-Varela) + VSM feedback |
| I-7 (self-attestation) | → | I-2 extended to kernel-resident adversary |
| I-9 (root reachability) | → | confused-deputy resistance |

**I-1 is the foundational invariant.** Every other invariant presupposes
a decidable policy language. Therefore every PR that touches the
dispatcher, handler tables, or ISA encoding must first verify I-1 is
preserved, then verify its target invariant.

---

## §11. Invariant summary table

| # | Invariant | Current enforcement | Known violations | Proposed strengthening |
|---|-----------|---------------------|------------------|------------------------|
| I-1 | Turing-incomplete ISA | Eyeball + `grep` shows zero self-emission | None (coupled to I-8) | ~60-120 LOC runtime assert + build-time static check (S75-S76) |
| I-2 | Destroy-on-read APE | Runtime `memzero_explicit` + spinlock | Cache/register/hibernation leak paths (defense-in-depth) | ~13 LOC total for CLFLUSH + clobber + `__nosave` (S75) |
| I-3 | Monotonic authority decay | Runtime sysfs counter + WARN | Counter never observed non-zero (runtime validation gap) | ~100 LOC adversarial test in `tests/adversarial/` (S75) |
| I-4 | Cortex-veto-only | Convention + pipeline order | Mechanical enforcement absent | ~80 LOC Python typestate + kernel `/dev/trust_cortex` (S75) |
| I-5 | No upward calls | Eyeball + `grep` | None | ~10 LOC CI lint (S75) |
| I-6 | Every producer has consumer | Does not exist today | 4 violations: algedonic reader, PE_EVT_EXCEPTION, mitokine channels, subsystem-stress event | ~40 LOC PR checklist + CI grep (S75) |
| I-7 | Self-attestation | Not implemented | N/A (aspirational) | ~300 LOC `trust_ape_verify_self` (S75+) |
| I-8 | Dispatch table `const __ro_after_init` | **CURRENTLY VIOLATED** at `trust_dispatch.c:1293` | Currently violated | S74 Agent 10 Task 3 (~40 LOC, in progress) |
| I-9 | Authority graph reachability | Partial (parent_id field enforced) | Thin test coverage | ~60 LOC periodic reachability walk + adversarial test (S75+) |

**What's already enforced:** I-2, I-3, I-5, I-9 (partial).

**Being fixed this session (S74):** I-8 (Agent 10 Task 3).

**S75 priority stack:** I-1 (strengthen), I-2 (cache/reg/hiber hardening),
I-4 (mechanical enforcement), I-6 (CI codification), I-7 (self-
attestation).

---

## §12. Closing notes

**These nine invariants are the architecture.** A system that
preserves all nine is an instance of the ARCHWINDOWS / Root-of-
Authority architecture. A system that violates one of them is *not*
an instance; it is a related-but-distinct system that may or may not
have similar security properties.

The distinction matters for:

- **Forks:** a fork that preserves the code but relaxes I-1 (e.g. adds
  a Lisp-style REPL to the ISA) is a different architecture, not a
  variant.
- **Paper revisions:** the paper's theorems are consequences of these
  invariants. A paper revision that adds a theorem without a
  corresponding invariant is incomplete.
- **Peer review:** reviewers should be directed to this document,
  not to the code directly. Invariants are the minimal sufficient
  review surface.

---

**End of architecture-invariants.md.**
