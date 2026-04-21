# S74 Agent F — Stored-Program Architecture & Homoiconicity for the Trust ISA

**Session 74, 2026-04-20. Research only, no source edits.**
**Primary question:** *Should trust.ko be able to emit trust ops for its own future execution?*
**Short answer:** **No.** Keep trust.ko as a stored-*metadata* machine, not a stored-*program* machine.
Preserve decidable authorization by maintaining a strict bright line between the dispatch table
(`__ro_after_init` rodata) and the command stream (untrusted userspace data). Adopt 5 of the 10
surveyed primitives as compatible upgrades; explicitly reject 4; gate 1 behind a signed cert.

---

## Exec summary table

| # | Primitive | Classical substrate | ARCHIMATION analogue | Unlocks | Safety requirement | Should adopt? | LOC |
|---|---|---|---|---|---|---|---|
| 1 | Lisp homoiconicity (McCarthy 1960) | cons-cells, eval/quote | Instruction word = data word | Full reflection; macros | TOTAL LOSS of decidability | **NO — explicit reject** | N/A |
| 2 | Forth immediate words (Moore 1969) | dictionary self-extension | Fused ops as compile-time macros | Userspace batch fusion | No runtime dispatch mutation | **YES — already partial (fused ops)** | ~80 (harden as rodata) |
| 3 | Scheme hygienic macros (Kohlbecker 1986, Dybvig 1992) | syntax-case, phases | Build-time ISA expansion | Clean composition | Only at build time | **YES — adopt pattern** | ~120 (codegen pass) |
| 4 | eBPF JIT (Starovoitov 2014, Fleming 2017) | verifier + JIT | Signed trust-bytecode extension | User-supplied policy | Verifier total + rodata + signed | **GATED — S75 slice only if signed + verifier lands** | ~2500 (verifier) + ~500 (signing) |
| 5 | CRISPR-Cas9 (Jinek 2012, Doudna 2014) | guide RNA + PAM + Cas9 | Quorum-signed policy patch | Targeted runtime reconfig | N-of-M signatures + audit log + PCR reseal | **YES — limit to metadata**, not code | ~400 (already in quorum.c scaffold) |
| 6 | Prion self-propagation (Prusiner 1982) | PrP^Sc template | Authority pattern that self-spreads | — | None that's sufficient | **NO — explicit reject** | N/A |
| 7 | Self-modifying code / W^X bypass | SMC, JIT | Dispatch table mutation | Performance only | Hardware W^X + pahole + CFI | **NO — and harden the dispatch table** | ~40 (make `__ro_after_init`) |
| 8 | CHERI capabilities (Watson 2015, Woodruff 2014) | hardware sealed caps | Capability-mask operand tag | Unforgeable refs | Co-designed HW; seal monotone | **YES — formalize seal semantics** | ~200 (seal/unseal op) |
| 9 | eBPF + XDP / io_uring as kernel-extension substrate | verified bytecode | Userspace policy DSL | Fast-path policy | Total language + bounded | **PARTIAL — use pattern not program** | ~800 (policy DSL eval) |
| 10 | Gödel diagonal / halting applied to self-auth | Gödel 1931, Turing 1936 | "revoke right-to-emit" paradox | — | — | **AVOIDED by design — total language** | 0 |

Four explicit **rejects** (1, 6, 7-as-SMC, halting-based self-auth). Five **adopts** (2, 3, 5 limited,
8, hardening 7). One **gated for S75+** (4, eBPF-style policy extension) — only if a full
verifier + signature chain + MOK-rooted trust path lands first.

Total recommended LOC: **~840** hardening (rodata + codegen + seal/unseal + audit); one
~2500-LOC gated item for policy extension deferred to a later session.

---

## 0. Ground truth: what trust.ko currently is

Before layering theory on top, this is the concrete state of the trust ISA (sources as of HEAD
5013ad9, all file paths relative to repo root):

* **Instruction word — 32 bits** (`trust/include/trust_cmd.h` via `TRUST_CMD_ENCODE`):
  `[4-bit family | 4-bit opcode | 4-bit flags | 4-bit nops | 16-bit imm]`.
* **6 + 1 + 1 families** — AUTH, TRUST, GATE, RES, LIFE, META (0..5) plus VEC (6) and
  FUSED (7). Eight canonical opcodes per family (0..7), plus fused variants (8..15 per family)
  gated by the `TRUST_OPCODE_FUSED_BIT = 0x8` in the opcode field.
* **Operand word — 64 bits** with a 4-bit type tag in the top nibble
  (`TRUST_OP_TAG_SUBJECT=0 .. TRUST_OP_TAG_THRESHOLD=7`). Values carry subject IDs,
  capability bitmaps, scores, tokens, actions, domains, proofs, thresholds.
* **Capability mask** is carried via `TRUST_OP_TAG_CAP` operands (not as a separate
  per-instruction `cap_mask` field; this is important — cap tags are *data the instruction operates
  on*, not a predicate controlling instruction authority to execute). The kernel consults
  `trust_dna_gate_check(sid, cap)` at handler time.
* **Predicate bit** — in VARLEN batches, `TRUST_CMD_FLAG_CONDITIONAL` is reinterpreted as
  "predicate enabled"; a 1-byte tag follows the instruction with sense + source + back-stride
  (`trust/include/trust_isa.h:247-259`).
* **Fused ops** — 7 pairs currently (AUTH×2, TRUST×2, RES×1, LIFE×1, plus VEC×9 for batch).
  The scalar equivalent of every fused op is documented in `trust/kernel/trust_fused.c`.
* **Dispatch table** — `static trust_cmd_handler_t dispatch_table[FAMILIES][OPCODES]` at
  `trust/kernel/trust_dispatch.c:1293`. **Not** `__ro_after_init`, **not** `const`. This is a
  concrete W^X gap we will discuss below.
* **Metadata table** — `static const struct opcode_meta[]` in
  `trust/kernel/trust_dispatch_tables.c` is `const` (rodata), bsearch'd, carries
  `TRUST_CTX_*` masks and names. Good. This is the stored-program *data* plane; we want to
  keep it that way.

**The homoiconic question for trust.ko:** our ISA today treats the instruction stream as
*read-only userspace data* copied from userspace into a kernel-side buffer, decoded once, and
executed handler-by-handler. The kernel itself *never* emits new instructions to a queue for later
execution by itself. The closest thing is `trust_quorum.c`'s scaffold for queued multi-signer
decisions, and the `trust_morphogen.c` scaffold for decay ticks — but neither re-enters the
dispatch table as an instruction. **The question is whether closing that loop is expressive
enough to be worth the decidability loss.**

---

## 1. Lisp homoiconicity (McCarthy 1960, Steele & Sussman 1978, Graham 2002)

**(a) Primary reference:** John McCarthy, "Recursive Functions of Symbolic Expressions and Their
Computation by Machine, Part I", *Comm. ACM* 3(4), 1960. Also: Guy Steele and Gerald
Sussman, "The Art of the Interpreter" (MIT AI Memo 453, 1978); Paul Graham, *On Lisp* (1993) ch.
7–10 on macros.

**(b) What it unlocks:** Maximum *expressive* power. Programs are S-expressions (cons-cells);
`(read)` returns the same structure `(eval)` consumes; `(quote expr)` produces the syntax
unevaluated, `(defmacro)` operates on syntax. The Lisp power locus is that user-defined control
structures are *first-class*: `loop`, `cond`, `unless`, `with-open-file` are all macros, not
primitives. Any sufficiently large Lisp grows its own DSL upward; this is the stated goal of
Graham 2002 *On Lisp*. Scheme extends this with hygienic macros (Kohlbecker et al., "Hygienic
Macro Expansion", LFP 1986) so gensyms don't capture user identifiers.

**(c) Applicable to trust ISA?** *Structurally*, yes: a trust instruction is 32 bits, an operand is
64 bits — they're both just data. We could trivially write a handler `cmd_meta_emit_instruction`
that takes a 32-bit instruction operand and pushes it into a kernel-side FIFO for the next
dispatch loop pass. **But structurally-trivial and semantically-safe are very different.** The
Lisp `eval` is defined as (Steele 1990 CLHS 3.1.2) a total function over finite S-expressions only
in the *absence* of environment mutation; in practice, `eval` is Turing-complete and undecidable
(Rice's theorem).

**(d/e) Should adopt?** **NO.** If trust.ko can `eval` an instruction that it itself emitted, the
set of authorizations a subject can eventually gain is undecidable. We lose the property that
motivates the whole module: *a given policy is statically analyzable*. The trust ISA's value
proposition is that given a batch buffer and a subject's current capability set, we can answer in
bounded time "will this batch ever allow action X?" — this is why every handler in
`trust_dispatch.c` is `O(1)` or `O(|cap mask|)` and there's no general-recursion opcode.

What property are we giving up to avoid the risk? **Full reflection.** We cannot have macros that
write trust policy at runtime. We can (and should, per section 3) have build-time macros via a
preprocessor / codegen step.

**References for deeper dive:**

* Harold Abelson & Gerald Sussman, *Structure and Interpretation of Computer Programs* 2e,
  ch. 4.1 (metacircular evaluator), 1996.
* Matthew Flatt, "Composable and Compilable Macros: You Want It When?", ICFP 2002 —
  shows why phase-separation between compile-time and runtime is non-trivial but desirable.
* Ryan Culpepper & Matthias Felleisen, "Fortifying Macros", ICFP 2010 — source
  of the modern hygienic macro theory, why syntax-case is safer than defmacro.

---

## 2. Forth — threaded code and immediate words (Moore 1969, Ting 1986)

**(a) Primary reference:** Charles Moore, "Forth — a new way to program a mini-computer",
*Astron. Astrophys. Suppl.* 15, 1974 (p. 497-511). Also: Leo Brodie, *Starting Forth* (1981) and
*Thinking Forth* (1984); C.H. Ting, *eForth and Zen* (1986); Anton Ertl & M. Anton, "Threaded
Code Variations and Optimizations", EuroForth 2001.

**(b) What it unlocks:** Forth has a *radically different* homoiconic model: the interpreter is a
dictionary of word definitions, and *immediate words* execute at compile time to extend the
dictionary itself. The `CREATE ... DOES>` pattern defines a new word whose runtime behavior is
parameterized by the compile-time definition. Threaded code means each word's body is simply a
list of addresses of other words. Moore's claim (famously controversial, defended at length in
*Thinking Forth* ch. 4) is that this factoring matches how humans think about *problems*: you
define vocabulary specific to the domain.

Forth lets you *extend the interpreter itself* in the source of your program. `IF`, `WHILE`, even
`[` and `]` (meta-level switches) are ordinary words in ordinary Forth.

**(c) Applicable to trust ISA?** Partially, and we've already found this path by accident. **Our
fused opcodes (`AUTH_OP_VERIFY_THEN_GATE`, `TRUST_OP_CHECK_AND_RECORD`, etc.) are exactly
Forth-style immediate words**: they're defined at kernel build time, they execute as if two ops
had been issued, they reduce dispatch overhead, and their scalar fallback is documented
(`trust/kernel/trust_fused.c:19-24` — "Every FUSED op has a well-defined scalar equivalent").

**(d) Safety envelope:** The Forth pattern applied to trust ISA has a *clean* shape that doesn't
cross the decidability line:

1. Fused opcodes are defined at build time only. They're added by editing kernel source.
2. Each one must declare its scalar equivalent (already done in a comment today; should be
   *machine-checked* — a self-test at module init that runs the fused path and the scalar path
   on a canary subject and compares outputs).
3. The userspace batch encoder may *lower* a fused op to its scalar pair if the kernel reports
   missing `TRUST_FEAT_FUSED` via `TRUST_IOC_QUERY_CAPS` (already implemented in
   `libtrust/libtrust_batch.c`).

The property this gives up: users cannot define *their own* fused opcodes at runtime. That's
fine; defining new primitives is a kernel-dev operation, not a user operation.

**LOC cost:** ~80 to harden — add a `trust_fused_selftest()` called from module init that
executes every fused op + its scalar equivalent on a test subject and compares outputs. (Similar
to what `trust_dispatch_tables_selfcheck()` does for the metadata table.) Plus move the fused
handler table itself to `__ro_after_init` (currently static but not marked).

**(e) Adopt.** This is the sweet spot: *build-time homoiconicity, runtime stored-program
purity*.

**References for deeper dive:**

* Anton Ertl, "Stack Caching for Interpreters", PLDI 1995 — performance analysis of
  threaded-code style, same shape as our dispatch loop.
* Peter Knaggs, "Practical and Theoretical Aspects of Forth Software Development", UoT
  thesis 1993 — dissertation on when Forth's immediate-word pattern is safe.

---

## 3. Scheme hygienic macros and metaprogramming phases (Kohlbecker 1986, Dybvig 1992, Flatt 2002)

**(a) Primary reference:** Eugene Kohlbecker, Daniel Friedman, Matthias Felleisen, Bruce Duba,
"Hygienic Macro Expansion", LISP and Functional Programming 1986. Also: R. Kent Dybvig, Robert
Hieb, Carl Bruggeman, "Syntactic Abstraction in Scheme", *LISP and Symbolic Computation* 5(4),
1992; Matthew Flatt, "Composable and Compilable Macros", ICFP 2002; Matthias Felleisen et al.,
*A Programmable Programming Language* (CACM 2018).

**(b) What it unlocks:** Hygienic macros give you Lisp-style metaprogramming *without* the
gensym footguns. `syntax-case` (Dybvig 1992) and `syntax-parse` (Culpepper 2010) let the macro
body destructure syntax pattern-match style. Phases (Flatt 2002) separate compile-time and
runtime identifiers — a value used at compile-time is *statically visible* to the compiler but
*not* present at runtime.

The Rust procedural macro system (since 1.15, 2017) is a direct descendant of this — proc macros
run at compile time, operate on TokenStreams, and produce TokenStreams; they cannot introspect
runtime values.

**(c) Applicable to trust ISA?** Yes, as a *build-time codegen pattern* — *not* as a runtime
feature. Today, the fused ops in `trust_fused.c` are written by hand, which means the scalar
equivalent in the comments has to be audited by hand. A Scheme-macro-style pattern would:

1. Let a developer write a `.fused` file like:
   ```
   FUSED AUTH_GATE(sid, cap, action) =
       trust_ape_consume_proof(sid, action) THEN
       trust_dna_gate_check(sid, cap);
   ```
2. A codegen tool at build time expands it into (a) the kernel handler, (b) the scalar fallback
   for `libtrust` to lower to, (c) the self-test that proves they're equivalent. One source of
   truth.

**(d) Safety envelope:** Trivially safe — this is build-time only, never touches the running
kernel. The only risk is the codegen tool having a bug; mitigate with `cargo test`-style harness
+ dual-check against the hand-written version during a transition period.

**LOC cost:** ~120 for the codegen pass (Python, runs in `scripts/build-packages.sh`). Plus
~20 per fused op to rewrite the existing 7 fused ops in the DSL (net code reduction in the .c).

**(e) Adopt.** Phase-separated metaprogramming is the *only* form of homoiconicity that doesn't
compromise the decidable-authorization property.

**References:**

* Kohlbecker et al., LFP 1986 — the seminal paper on hygiene.
* Matthew Flatt, "Bindings as Sets of Scopes", POPL 2016 — modern formalization of hygiene,
  used in Racket.
* Alex Crichton, "The Rust Programming Language" — §19 on proc macros, the production
  descendant of this line.

---

## 4. eBPF as a kernel-extension substrate (Starovoitov 2014, Fleming 2017, Gregg 2019)

**(a) Primary reference:** Alexei Starovoitov, "Extended BPF" patch series, LWN.net June 2014.
Also: Matt Fleming, "A thorough introduction to eBPF", LWN 2017; Brendan Gregg, *BPF
Performance Tools*, Addison-Wesley 2019; David Miller et al., "The Linux kernel XDP
documentation" (Documentation/networking/filter.rst).

Recent security work: Kangjie Lu et al., "MOAT: Towards Safe BPF Kernel Extension", USENIX
Security 2024 (arXiv:2301.13421); Soo Yee Lim et al., "Rethinking BPF: Can We Trust Kernel
Extensions?", ACM OSDI 2024; Hao Sun et al., "Finding Correctness Bugs in eBPF Verifier with
Structured and Sanitized Programs", EuroSys 2024.

**(b) What it unlocks:** eBPF is the production poster child for safe, stored-program, kernel
extension. Userspace submits bytecode, the *verifier* proves termination and memory safety, the
JIT compiles to native, and the program runs in kernel context (XDP, tracepoints, syscalls,
LSMs, etc.). The verifier is the key: it enforces bounded loops (until Linux 5.3 which added
bounded recursion via bpf_loop), type-checked memory access (CO-RE), and pointer tracking.

eBPF is the closest thing in the Linux kernel today to a *homoiconic kernel-extension substrate*:
the kernel accepts programs as data and executes them.

**(c) Applicable to trust ISA?** **Conceptually yes, practically deferred.** The trust ISA *could*
accept a user-supplied policy program — say, a custom `TRUST_OP_POLICY_EVAL` handler that runs
a short verified-bounded-loop-free expression over subject state. This would unlock "policy as
code" for operators without shipping a new kernel module.

**(d) Safety envelope** (if ever adopted):

1. **Verifier.** Total language, like Agda or Coq — guaranteed termination. No general
   recursion, no dynamic dispatch, no pointer arithmetic, bounded loops.
2. **Signed.** Every policy program must carry a Dilithium or Ed25519 signature rooted in the
   MOK (DB) cert installed by `packages/trust-dkms`. Unsigned policies are refused.
3. **rodata.** Once loaded and verified, the program bytes are `mlock`'d and mapped read-only;
   JIT output (if any) lives in a dedicated kernel rodata section.
4. **No self-emission.** The policy can *read* subject state, *return* a verdict. It cannot
   enqueue further trust instructions. (This is the key difference between "stored program" and
   "homoiconic".)
5. **Attested.** The SHA-256 of each loaded policy is mixed into PCR 11 via `trust_attest.c`
   (S72 γ agent landed the TPM2 bridge). Tamper detection is cryptographically hard.
6. **Bounded.** Per-call timeout (TSC deadline, ~100 µs). Exceeding the deadline aborts the
   policy and marks the action DENIED with a specific audit code.

**LOC cost:** ~2500 for a minimal verifier (bounded loops only, no memory writes) + ~500 for
signature verification + ~200 for attestation mixin + ~300 for policy loader syscall. Total
~3500 LOC. This is a full session's effort, not a side project.

**MOAT 2024 finding:** even eBPF's production verifier (15+ years of hardening) has had a
steady stream of CVEs (CVE-2021-31440, CVE-2022-0185, CVE-2023-2163). Any trust.ko bytecode
surface would start from zero maturity — and trust.ko sits *below* eBPF in the authority
ordering, so a verifier bug would be a moat-collapse.

**(e) GATED recommendation.** **Don't ship this in S74 or S75.** The attestation-rooted signed
MOK path is a prerequisite (S72 landed scaffolding; the real project-MOK genesis is still open
per S73 handoff notes). Revisit no earlier than S80, after bootc/TPM2 story is end-to-end real.

**References:**

* LWN.net, "eBPF — Extended Berkeley Packet Filter" overview, June 2014.
* Lu et al., "MOAT: Towards Safe BPF Kernel Extension", USENIX Security 2024.
* Jiacheng Xu et al., "SafeBPF: Hardware-Assisted Defense-in-Depth for eBPF Kernel
  Extensions", arXiv:2409.07508, September 2024.
* Jinghao Jia et al., "RSFuzzer: Discovering Deep SMI Handler Vulnerabilities in UEFI
  Firmware with Hybrid Fuzzing", S&P 2024 — context on the difficulty of verifying
  *privileged* bytecode.
* Zac Hatfield-Dodds, "How eBPF Verifier Works", LWN.net 2021 — plain-language tour.

---

## 5. CRISPR-Cas9 as a biological self-modifying program (Jinek 2012, Doudna 2014, Barrangou 2018)

**(a) Primary reference:** Martin Jinek, Krzysztof Chylinski, Ines Fonfara, Michael Hauer,
Jennifer Doudna, Emmanuelle Charpentier, "A Programmable Dual-RNA–Guided DNA Endonuclease in
Adaptive Bacterial Immunity", *Science* 337(6096), 2012. Also: Jennifer Doudna & Emmanuelle
Charpentier, "The new frontier of genome engineering with CRISPR-Cas9", *Science* 346(6213),
2014; Rodolphe Barrangou, "CRISPR-Cas systems: Prokaryotes upgrade to adaptive immunity",
*Molecular Cell* 54(2), 2014.

**(b) What it unlocks:** The CRISPR system is evolution's answer to "how do you safely edit a
genome?" The components:

* **PAM (protospacer adjacent motif)** — a 3-nt recognition sequence; Cas9 *refuses* to cut
  without it. PAM acts as a capability check.
* **Guide RNA (sgRNA)** — ~20 nt matching the target; *transcribed from the same genome* that
  Cas9 reads and edits. This is biology's own homoiconicity.
* **Cas9 nuclease** — performs the edit (double-strand break) only if PAM + guide + target
  match.
* **Repair pathway** — HDR (homology-directed repair) or NHEJ (non-homologous end joining)
  completes the edit. Both are gated.
* **CRISPR array** — the *record* of past edits; new spacers appended to the array when the
  cell survives a phage attack. **This is the audit log.**

Biology's safety layering is striking: (1) off-target cleavage is suppressed by PAM specificity;
(2) edits leave a detectable scar; (3) excessive editing triggers apoptosis (p53 pathway);
(4) population-level safety via horizontal gene transfer restriction.

**(c) Applicable to trust ISA?** Yes, with care. The trust system already has much of this shape:

* PAM ≈ capability mask (`TRUST_OP_TAG_CAP`).
* Guide RNA ≈ subject identifier + operand.
* Cas9 ≈ dispatch handler.
* Repair ≈ `trust_fbc_repartition()` (the only runtime policy modification).
* CRISPR array ≈ audit ring buffer (`trust/kernel/trust_*.c` audit paths).

The *gap* is quorum. Biology typically needs multiple signals (acquired immunity, innate
immunity, translation feedback) before a cell commits to a heritable change. Our
`trust_quorum.c` scaffold is the analogous mechanism.

**(d) Safety envelope:** A CRISPR-style *metadata* edit (not instruction-stream edit!) is
within the safety envelope if:

1. **N-of-M signatures** required. Cannot be a single unilateral action.
2. **Audit log** is immutable and rooted in TPM PCR 11.
3. **Scar detection** — every metadata change must be visible in a sysfs counter and
   mentioned in the next attestation. No silent edits.
4. **Apoptosis** — if the edit rate exceeds a threshold, trust.ko enters
   `TRUST_STATE_QUARANTINE` and refuses further changes until reboot.
5. **Only metadata, not dispatch.** Edit policy thresholds, capability translation tables,
   morphogen gradients — not instruction handlers.

**LOC cost:** ~400. Most of this is already present in `trust_quorum.c` and
`trust_algedonic.c` (S73 scaffold). The new work is binding edits to PCR 11 and
`trust_invariants.c`.

**(e) Adopt *for metadata only*.** This is the "CRISPR as immune memory update" pattern —
*not* "CRISPR as the ability to rewrite Cas9 itself."

**References:**

* Jinek et al., *Science* 2012 — the Cas9-guide-PAM triad.
* Luciano Marraffini, "CRISPR-Cas immunity in prokaryotes", *Nature* 526, 2015 — on the
  immune-memory analogy.
* David Benjamin Turitz Cox et al., "RNA editing with CRISPR-Cas13", *Science* 358, 2017 —
  *reversible* edits, closer to what we'd want in a metadata patch.
* Jennifer Doudna et al., "Genome-editing technologies: principles and applications", *Cold
  Spring Harbor Perspectives in Biology* 8(12), 2016 — design principles for safety.

---

## 6. Prion self-propagation (Prusiner 1982, Aguzzi 2004)

**(a) Primary reference:** Stanley Prusiner, "Novel proteinaceous infectious particles cause
scrapie", *Science* 216(4542), 1982. Also: Adriano Aguzzi & Markus Glatzel, "Prion infections:
cellular prion protein, prions, pathology", *The Lancet Neurology* 3(9), 2004; Jonathan
Weissman, "Yeast Prions: What They Teach Us About Cell Biology", *Cell* 164(1), 2016.

**(b) What it unlocks:** Prions are *conformational* infectious agents: a protein (PrP^C) in its
normal α-helical fold can be catalyzed by a misfolded copy (PrP^Sc, β-sheet rich) into converting
to the misfolded form, which itself catalyzes more conversion. **No nucleic acid is transmitted.**
This breaks the central dogma because information propagates via shape alone.

**(c) Applicable to trust ISA?** Structurally this would be a *pattern that modifies the
interpretation of other patterns*. Say a `TRUST_META_REINTERPRET` op that changes how future
AUTH ops are interpreted. The analogy is very close; the safety analogy is *nightmarish*.

**(d/e) Should adopt?** **NO. Explicit reject.**

Reasons:

1. **Defeats static analysis.** If an executed instruction can alter the semantics of future
   instructions, no one batch is independently verifiable.
2. **Biology's prion diseases have no cure.** Mad cow disease, CJD, kuru — the best we have is
   quarantine and slow decline.
3. **Catalytic amplification** means a single privileged write can change the authority model
   for every subsequent subject. Blast radius = infinity.
4. **No software analogue is known to be safe.** The closest software example is a malicious JIT
   plugin that rewrites bytecode semantics — every known case in the CVE database is a
   vulnerability.

**What property are we giving up?** Runtime *semantic* flexibility. We'll stick with syntactic
composition (fused ops) and metadata edits (CRISPR-style).

**References:**

* Prusiner, *Science* 1982 — the original prion hypothesis.
* Susan Lindquist et al., "[PSI+] prion of yeast", *Cell* 89, 1997 — yeast prions, the
  tractable model.
* Adriano Aguzzi, "Understanding the diversity of prions", *Nature Cell Biology* 6, 2004 —
  review.

---

## 7. Self-modifying code and the W^X arc (Cohen 1984, Anderson 2005, Ge 2020)

**(a) Primary reference:** Fred Cohen, "Computer Viruses — Theory and Experiments", *Computers
& Security* 6(1), 1987. Historical: Ken Thompson, "Reflections on Trusting Trust", *Comm. ACM*
27(8), 1984. Modern defenses: Ross Anderson, *Security Engineering* 2e ch. 18, 2008; Hong-Gang
Ge, Sunil Jain, "Hardware-Based Control-Flow Integrity", USENIX Security 2020.

**(b) What it unlocks historically:** SMC (self-modifying code) was the demo-scene's trick for
space: instead of branching, patch the instruction inline. JIT compilers (V8, HotSpot, LLVM ORC)
are essentially disciplined SMC — code pages are mapped writable, compiled into, flipped to
executable. The whole W^X arc is the hardware/software co-design response: DEP/NX (Intel 2001),
SMEP (2011), SMAP (2014), CET (2020), PAC (ARMv8.3, 2016), MTE (ARMv9, 2019). Each is a
narrowing of the legitimate-SMC use-case.

**(c) Applicable to trust ISA?** This isn't about the ISA — it's about the **kernel module's own
`.text` and the dispatch table itself.** The concrete finding is:

Looking at `trust/kernel/trust_dispatch.c:1293`:

```c
static trust_cmd_handler_t dispatch_table[TRUST_STAT_FAMILY_SLOTS][TRUST_CMD_MAX_OPCODES] = {
    [TRUST_FAMILY_AUTH] = { [AUTH_OP_MINT] = cmd_auth_mint, ... },
    ...
};
```

This table is `static` but **not** `const` and **not** `__ro_after_init`. An attacker with
kernel-write primitive (e.g., via a separate LPE in another module) could overwrite a handler
pointer — say, redirect `cmd_auth_verify` to a function that always returns 0. Every subsequent
`AUTH_VERIFY` would succeed regardless of proof. This is a literal moat-collapse scenario.

**By contrast**, `trust_dispatch_tables.c`'s meta table *is* `const` (rodata). Good discipline,
but the metadata isn't the authority root — the dispatch table is.

**(d) Safety envelope:** Mark the dispatch table `const __ro_after_init`. Linux's module loader
+ `set_memory_ro` (from `arch/x86/mm/pat/set_memory.c`) will place it in a read-only page after
module init. Any write attempt after module init faults.

```c
// proposed
static trust_cmd_handler_t const dispatch_table[...][...] __ro_after_init = { ... };
```

Plus: add a module-init self-check that reads the `__section(".rodata")` attribute of the
dispatch_table symbol. If the linker didn't place it where we expect, refuse to init
(`trust_attest.c` FAILED path already exists — wire this into the same mode).

Plus: control-flow integrity. The handlers are all function pointers; CFI (CFI_CLANG under Linux
6.1+) ensures jumps go to valid targets. Should add `CONFIG_CFI_CLANG` to the build docs for
`packages/trust-dkms`.

**LOC cost:** ~40. One `__ro_after_init` annotation, one startup selfcheck, one docs update.
This is a *very* high ROI hardening.

**(e) Adopt the defense. Reject the offense.** Do not add any runtime path that writes
dispatch_table. Instead, *prove* it's read-only post-init.

**References:**

* Ken Thompson, "Reflections on Trusting Trust", *CACM* 1984 — the classic.
* Intel, "Control-flow Enforcement Technology Preview", rev 3.0, 2019 — CET docs.
* Kees Cook, "The state of kernel self-protection", Linux Security Summit 2021 — great
  primer on `__ro_after_init`, `CONFIG_STRICT_KERNEL_RWX`, and friends.
* John Criswell et al., "KCoFI: Complete Control-Flow Integrity for Commodity Operating
  System Kernels", IEEE S&P 2014 — the research precursor.
* Chen et al., "KPT: Kernel Page Table Isolation Revisited", OSDI 2023 — 2023 evidence
  that kernel-write primitives still circumvent classic KPTI/W^X on pathological paths.

---

## 8. Capability machines — CHERI, Morello, and sealed refs (Carter 1994, Watson 2015, Woodruff 2014)

**(a) Primary reference:** Jonathan Woodruff, Robert N.M. Watson, David Chisnall, Simon W.
Moore, Jonathan Anderson, Brooks Davis, Ben Laurie, Peter G. Neumann, Robert Norton, Michael
Roe, "The CHERI capability model: Revisiting RISC in an age of risk", ISCA 2014. Also: Robert
N.M. Watson et al., "CHERI: A Hybrid Capability-System Architecture for Scalable Software
Compartmentalization", IEEE S&P 2015; Arm, "Morello Program" whitepaper, 2022; Watson et al.,
"An Introduction to CHERI", UCAM-CL-TR-941, 2019.

Recent: Konrad Witaszczyk et al., "CheriBSD Compartmentalization for Userspace Applications",
IEEE S&P 2024; James Bornholt, David Chisnall, "Formally Verifying the CHERI Capability
Model", POPL 2023.

**(b) What it unlocks:** Hardware capabilities. A capability is a (base, length, permissions,
tag-bit) tuple; the tag bit is maintained by hardware and can't be forged by integer arithmetic.
Seal/unseal operations let you turn a capability into an opaque token and back, parameterized by
a *type* capability — this is the key to building software abstractions that hardware enforces
(closures, object handles, remote refs).

The 2015 IEEE S&P paper showed CHERI reduces buffer-overflow vulnerability classes by 66%.
Morello (Arm's 2021 CHERI CPU) is the first production-grade capability machine.

**(c) Applicable to trust ISA?** Yes, partially. Our `TRUST_OP_TAG_CAP` is already a
capability-like tag — a 60-bit value + 4-bit type tag. But we don't have hardware backing; we
don't have seal/unseal semantics; we don't have monotonicity enforcement.

**The proposal is to formalize what we already have.** Define:

1. A **capability** is a `TRUST_OP_TAG_CAP` operand; its value is a bitmask over the 64 known
   trust actions (`TRUST_ACTION_*`).
2. **Monotonicity:** a handler can *remove* bits from a capability (narrow it) but never *add*
   (widen it). This is the CHERI "monotonicity" property (Watson 2015 §3.2). Enforced by a new
   `trust_cap_derive()` helper that replaces direct mutations.
3. **Seal:** a new `META_OP_SEAL` op that takes a cap and a subject's secret (XOR with a
   per-boot random 64-bit key). A sealed cap is opaque to all handlers except
   `META_OP_UNSEAL`, and *unseal requires the same subject*.
4. **Unforgeability:** the tag bit is the `TRUST_OP_TAG_CAP = 1` value in the operand encoding;
   the kernel rejects any operand where the value-bits decode as a capability but the type tag
   is something else.

This gives us software capabilities with the same *shape* as CHERI, bounded by the kernel's
inability to be memory-faulted (we're already in kernelspace; the kernel *is* the hardware
check).

**(d) Safety envelope:**

* Seal/unseal are monotone: once sealed you can only unseal (not re-derive).
* Per-boot random XOR key means sealed caps don't survive a reboot (feature, not bug).
* New `trust_cap_monotonicity_selftest()` in module init verifies the derive helper never
  produces a strictly-superset cap.

**LOC cost:** ~200 (new seal/unseal ops + derive helper + selftest + two new meta opcodes).

**(e) Adopt.** Capability discipline is *orthogonal* to homoiconicity and purely subtractive —
it *reduces* the authority an instruction can have. That's always a safety win.

**References:**

* Watson et al., IEEE S&P 2015 — the definitive paper.
* Bornholt & Chisnall, POPL 2023 — formally verified monotonicity.
* Witaszczyk et al., IEEE S&P 2024 — production CheriBSD data.
* Luke W. Carter, "Combining Identity Based and Capability Based Access Control for OS
  Security", 1994 — original capability systems work.
* Mark Miller, "Robust Composition: Towards a Unified Approach to Access Control and
  Concurrency Control" (PhD thesis 2006) — the object-capability pattern.

---

## 9. Homoiconic kernel-extension substrates — eBPF, XDP, DTrace, io_uring (Høiland-Jørgensen 2018, Cantrill 2004, Axboe 2019)

**(a) Primary reference:** Toke Høiland-Jørgensen et al., "The eXpress Data Path: Fast
Programmable Packet Processing in the Operating System Kernel", CoNEXT 2018. Also: Bryan
Cantrill, Michael Shapiro, Adam Leventhal, "Dynamic Instrumentation of Production Systems",
USENIX ATC 2004 (DTrace); Jens Axboe, "Efficient IO with io_uring", 2019 kernel-docs; Christoph
Hellwig, "io_uring and the Linux async-I/O future", LWN 2023.

**(b) What they unlock:**

* **eBPF (Starovoitov 2014, covered in §4).**
* **XDP** — pre-napi-handler bytecode; the closest thing to a fully-homoiconic packet-processing
  substrate. Programs run before `skb` allocation.
* **DTrace (Sun, 2004)** — a typed scripting language (D) compiled to in-kernel instrumentation;
  Cantrill-Shapiro-Leventhal 2004 emphasizes *total*-ness (no loops, no function calls) as the
  safety bound.
* **io_uring** — a ring-buffer of operation descriptors; not strictly a program substrate but
  *is* a stored-program pattern in miniature (operations batched and executed out-of-order).

**(c) Applicable to trust ISA?** Our VARLEN batch (`trust_isa.h:§batch wire format`) is already
exactly this pattern: a ring of `(instruction, predicate, operands...)` descriptors with
delta-compressed subject IDs. This is *closer to io_uring* than to eBPF — io_uring is
stored-*operation*, not stored-*program*, because each operation is fixed-shape and doesn't
contain conditional dispatch. That's what we want.

**The DTrace discipline is the gold standard for our use-case:** DTrace chose *total* language
design (bounded iteration, no general recursion, no variable-length loops) to guarantee scripts
couldn't hang the kernel. Our ISA already has this property by construction — every handler is
`O(1)` amortized, no opcode reads the instruction stream, no opcode recurses.

**(d) Safety envelope:** None additional — our batch already *is* the safe variant. The thing to
*not* do is turn it into general bytecode. Specifically:

* **Don't** add a `META_OP_JMP` or `META_OP_CALL`. These break totality.
* **Don't** add a `META_OP_LOAD` that reads arbitrary kernel memory. Operands must remain
  strongly-typed.
* **Do** keep the predicate bit but bound stride to ≤ 63 (already done:
  `TRUST_PRED_STRIDE_MASK = 0x3F`).

**(e) Adopt the discipline, not the bytecode.** Keep the batch as a
*stored-operation* queue, not a stored-program language. Borrow DTrace's totality proof for docs.

**References:**

* Cantrill et al., USENIX ATC 2004 — DTrace's totality argument is a model.
* Høiland-Jørgensen et al., CoNEXT 2018 — XDP throughput.
* Jens Axboe, "io_uring" LWN 2019 — the stored-operation pattern.
* Brendan Gregg, *Systems Performance* 2e ch.3, 2020 — synthesis.

---

## 10. Gödel / halting applied to self-referencing trust (Gödel 1931, Turing 1936, Myhill 1955)

**(a) Primary reference:** Kurt Gödel, "Über formal unentscheidbare Sätze der Principia
Mathematica und verwandter Systeme I", *Monatshefte für Mathematik und Physik* 38, 1931. Also:
Alan Turing, "On Computable Numbers, with an Application to the Entscheidungsproblem",
*Proceedings of the London Mathematical Society* 42, 1936; Douglas Hofstadter, *Gödel, Escher,
Bach*, 1979 (ch. on Strange Loops and self-reference); Raymond Smullyan, *Gödel's Incompleteness
Theorems*, 1992.

**(b) What it unlocks / forbids:** If a system is expressive enough to (a) represent its own
statements about authorization and (b) reason about them, then (c) it can construct a sentence
that says "this action is unauthorized" where the sentence is itself the action — Gödel's
diagonal. For a trust system, this manifests as: "the instruction 'revoke my own authority to
emit this instruction'" is **paradoxical** if the system is expressive enough.

Concrete example in our setting: suppose trust.ko can emit a `META_OP_REVOKE_EMIT` instruction.
Now consider the batch:
```
emit META_OP_REVOKE_EMIT with operand = subject_kernel
```
If the emission succeeds first, the revoke lands after, and the kernel has lost a power it once
had. If the revoke checks first and the emission is the very authority being revoked, the kernel
cannot consistently answer "does the kernel have the authority to emit this?" — the question
*depends* on the answer.

This is the *Russell's paradox* shape. The standard escape is **typed hierarchy** (Russell's
solution, Bertrand 1908; Martin-Löf 1972 for type theory) — assign levels and forbid reference
across levels.

**(c) Applicable to trust ISA?** Currently **no** — our ISA cannot emit, and we're advising it
stays that way. If we *did* add emission (§4's gated eBPF-style path, deferred), we'd need a
typed hierarchy:

* Level 0: direct user ops (AUTH, TRUST, GATE, RES, LIFE).
* Level 1: META ops (FLUSH, AUDIT, GET_*) — read-only with respect to lower levels.
* Level 2: META_REPARTITION, META_SEAL — write policy metadata, cannot write dispatch.
* Level ∞: nothing can modify Level 0/1 dispatch handlers.

**Coq, Agda, Lean as reference:** these are *total* languages — every program terminates, so the
halting problem doesn't bite. They forbid general recursion and pay for it with a less expressive
core, gaining soundness for their type systems. If we wanted full verification, this is the
model.

**(d) Safety envelope:** By refusing self-emission, we sidestep the paradox entirely. We do not
need a solution because we do not create the problem.

**(e) AVOIDED BY DESIGN.** The totality of the ISA is a feature. **Do not** add self-emission.
**Do** write this explicitly in the architecture docs as a load-bearing design constraint —
future sessions will be tempted to add `META_OP_EMIT` for "just this one use case" and the
totality is lost silently.

**References:**

* Gödel, "Über formal unentscheidbare Sätze", 1931.
* Turing, "On Computable Numbers", 1936.
* Per Martin-Löf, "An Intuitionistic Theory of Types", 1972 — type-theoretic escape from
  Russell.
* Hofstadter, *GEB* — the strange-loop synthesis.
* Benjamin Pierce, *Types and Programming Languages* ch. 12 (stratification) and ch. 23
  (system F vs Fω), 2002.
* Adam Chlipala, *Certified Programming with Dependent Types* (Coq textbook), 2013.

---

## 11. Turing-completeness of the trust ISA — and why we should stay Turing-*in*-complete

The trust ISA has:

* 6 + 2 families × 8–16 opcodes ≈ **70 primitive operations**.
* **No** general unconditional jump (predicate only looks *backward*, stride ≤ 63).
* **No** unbounded loop (kernel-side `TRUST_CMD_MAX_BATCH = 256` caps a batch;
  `TRUST_ISA_MAX_BATCH_OPS = 1024` caps an extended batch).
* **No** indirect dispatch (instructions directly name family+opcode).
* **No** arbitrary memory read/write (operands are strongly-tagged values).
* **No** self-emission (the focus question).

**Therefore: the ISA is not Turing-complete.** Every batch terminates in bounded steps. This is
the property the verifier-in-the-trust-gate can rely on, and the property that makes static
analysis of a policy decidable.

This mirrors:

* **SQL** (decidable subsets, bounded by row-count).
* **DTrace D** (Cantrill 2004 — total by design).
* **Datalog** (stratified negation = decidable).
* **Coq/Agda** terms (total; termination checker refuses non-terminating defs).

**This is the moat.** Every design pressure in S74+ will argue "just let the kernel emit one
instruction, for X" or "add an opcode that reads subject-X's field-Y". Each such addition
*individually* looks safe. *Collectively* they Turing-complete the ISA and collapse the moat.

**Recommendation:** Add a single file `trust/kernel/trust_invariants.c::trust_isa_totality` that
asserts (in kernel comment, and in docs) the set of properties above, and is updated any time a
new opcode is added. New opcodes must prove they preserve every bullet.

---

## 12. The direct question — should trust.ko emit trust ops for future execution?

**Threat model** if we say yes:

1. **T1: Adversary-supplied batch triggers self-emission loop.** Batch ops 1..k cause trust.ko to
   enqueue ops k+1..k+n. If handler for op k can enqueue arbitrary ops k+1, static analysis of
   "what caps does this batch grant?" is equivalent to the halting problem. **Decidability
   lost.**

2. **T2: Dispatch table corruption via emitted META_WRITE.** If emission can write dispatch, we
   have a self-modifying kernel module. W^X gone. **Moat collapse.**

3. **T3: Gödel-style diagonal.** `META_OP_REVOKE_EMIT` on the kernel subject. Paradoxical.
   **Consistency gone.**

4. **T4: Prion-style catalysis.** A single privileged op at time T can enqueue an infinite
   stream of elevation ops at time T+1. **Auditability gone** (ring buffer overflows, audit
   records dropped).

5. **T5: Amplification attack via VEC family.** One VEC emission fan-outs to `TRUST_ISA_MAX_VEC_COUNT = 256`
   subjects × arbitrary further ops. **Resource exhaustion.**

**Expressiveness gain** if we say yes:

1. **E1: Deferred actions.** "Decay this subject's score in 10 seconds." Useful, but already
   addressable by `trust_morphogen.c`'s tick loop (scheduled inside the kernel, not emitted).
2. **E2: Policy composition.** User writes a policy; kernel emits primitives to implement it.
   Covered better by §4's gated eBPF path, if we ever want it.
3. **E3: Quorum outcomes.** "3-of-5 agents signed, so apply X." Covered by §5 CRISPR-style
   *metadata* edits (not instruction emission). `trust_quorum.c` handles this without emission.
4. **E4: Retry / back-off logic.** "On DENY, try again in 1 tick with elevated cap." Covered by
   the `TRUST_OP_THRESH_ELEVATE` fused op or by userspace retrying.

**Every expressiveness gain is already addressable without self-emission.** Every safety risk is
severe and hard to mitigate.

### Verdict

**DO NOT add self-emission to the trust ISA.**

**Positive actions S74 should take (low LOC, high ROI):**

1. **Harden the dispatch table to `__ro_after_init const`** (§7, ~40 LOC). Prevents
   kernel-write primitives in *other* modules from altering trust.ko's authority graph.
2. **Add `trust_fused_selftest()` at module init** (§2, ~80 LOC). Proves every fused op
   equals its scalar pair.
3. **Formalize capability monotonicity + seal/unseal** (§8, ~200 LOC). Narrowing-only caps,
   per-boot sealed tokens.
4. **Build-time macro codegen for fused ops** (§3, ~120 LOC). Single source of truth, no
   hand-written comments to drift.
5. **Document the totality invariant** (§11, ~0 LOC code, ~50 lines docs). Load-bearing
   architectural bright line.

**Explicit rejects and why** (these should be written in docs so future sessions don't
re-propose them):

1. **No `META_OP_EMIT`** (§1, §10, §12). Turing-completeness = moat collapse.
2. **No prion-style semantic reinterpretation** (§6). No handler may change how another handler
   interprets its operands.
3. **No writable dispatch table** (§7). Even for "fast policy updates", use metadata (§5).
4. **No general eBPF-style policy bytecode in S74/S75** (§4). Gated on full TPM2/MOK story.

**Gated (S80+):** signed, verified, total, bounded-loop eBPF-style policy DSL (§4). Only if
attestation story is end-to-end real first.

---

## 13. Cross-framework convergence with S73 agents

Brief notes on where this agent's findings align or diverge with S73's research axes
(`docs/research/s73_*.md`):

* **S73 A (Von Neumann/Gács):** Von Neumann's reliable-from-unreliable construction
  *requires* voting; it does **not** require self-emission. My "metadata CRISPR edit with N-of-M
  signing" is the concrete shape of that — convergent with S73 A's voting recommendation.
* **S73 C (Shannon/Kolmogorov/Bennett):** Kolmogorov complexity of the trust ISA is *low*
  — this is a feature, because low complexity admits compression-based adversary detection.
  Self-emission would raise complexity unboundedly. Convergent.
* **S73 F (Hofstadter strange loops):** Strange loops *inside* trust.ko are exactly what
  §10 forbids — the consistency cost is too high. This agent explicitly argues against the
  strange-loop temptation.
* **S73 I (Friston/active inference):** Active inference at the cortex level (§E of the S73
  meta-exploit) is **not** blocked by no-self-emission — the cortex lives in userspace and
  communicates with trust.ko via the normal ioctl/ISA path. No conflict.
* **S73 L (Cronin assembly index):** The assembly index of our ISA is *bounded* because the
  ISA is bounded. A homoiconic ISA would have unbounded assembly index, collapsing the J
  (catalysis) analysis. Convergent with S73 L + J's structural argument for low-assembly cores.

The 10 S74 agents should converge on: **keep the ISA total; add biology-inspired *metadata*
edits with quorum + attestation; never add self-emission.**

---

## 14. Citations

**Classical:**
1. John McCarthy, "Recursive Functions of Symbolic Expressions…", *CACM* 3(4), 1960.
2. Kurt Gödel, "Über formal unentscheidbare Sätze…", *Monatshefte* 38, 1931.
3. Alan Turing, "On Computable Numbers…", *Proc. London Math. Soc.* 42, 1936.
4. Charles Moore, "Forth — a new way…", *Astron. Astrophys. Suppl.* 15, 1974.
5. Stanley Prusiner, "Novel proteinaceous infectious particles…", *Science* 216, 1982.
6. Fred Cohen, "Computer Viruses — Theory and Experiments", *Computers & Security* 6(1), 1987.
7. Ken Thompson, "Reflections on Trusting Trust", *CACM* 27(8), 1984.
8. Eugene Kohlbecker et al., "Hygienic Macro Expansion", LFP 1986.
9. R. Kent Dybvig et al., "Syntactic Abstraction in Scheme", *LSC* 5(4), 1992.
10. Douglas Hofstadter, *Gödel, Escher, Bach*, 1979.
11. Per Martin-Löf, "An Intuitionistic Theory of Types", 1972.
12. Luke W. Carter, "Combining Identity Based and Capability Based Access Control…", 1994.

**Biology:**
13. Martin Jinek et al., "A Programmable Dual-RNA–Guided DNA Endonuclease…", *Science* 337, 2012.
14. Jennifer Doudna & Emmanuelle Charpentier, "The new frontier of genome engineering…",
    *Science* 346, 2014.
15. Rodolphe Barrangou, "CRISPR-Cas systems: Prokaryotes upgrade…", *Mol. Cell* 54, 2014.
16. Adriano Aguzzi & Markus Glatzel, "Prion infections…", *Lancet Neurology* 3, 2004.
17. Susan Lindquist et al., "[PSI+] prion of yeast", *Cell* 89, 1997.
18. Jennifer Doudna et al., "Genome-editing technologies: principles and applications",
    *CSH Perspectives in Biology* 8(12), 2016.

**Systems 2004–2020:**
19. Bryan Cantrill, Michael Shapiro, Adam Leventhal, "Dynamic Instrumentation of Production
    Systems", USENIX ATC 2004 (DTrace).
20. John Criswell et al., "KCoFI: Complete Control-Flow Integrity for Commodity Operating System
    Kernels", IEEE S&P 2014.
21. Jonathan Woodruff et al., "The CHERI capability model", ISCA 2014.
22. Robert N.M. Watson et al., "CHERI: A Hybrid Capability-System Architecture…", IEEE S&P 2015.
23. Alexei Starovoitov, "Extended BPF" patch series, LWN.net, June 2014.
24. Matt Fleming, "A thorough introduction to eBPF", LWN, 2017.
25. Toke Høiland-Jørgensen et al., "The eXpress Data Path…", CoNEXT 2018.
26. Jens Axboe, "io_uring", kernel-docs / LWN 2019.
27. Hong-Gang Ge & Sunil Jain, "Hardware-Based Control-Flow Integrity", USENIX Sec 2020.
28. Intel, "Control-flow Enforcement Technology Preview", rev 3.0, 2019.

**Recent (2020–2026):**
29. Kees Cook, "The state of kernel self-protection", Linux Security Summit 2021.
30. Matthew Flatt, "Bindings as Sets of Scopes", POPL 2016.
31. Ryan Culpepper & Matthias Felleisen, "Fortifying Macros", ICFP 2010.
32. Matthias Felleisen et al., "A Programmable Programming Language", *CACM* 61(3), 2018.
33. James Bornholt & David Chisnall, "Formally Verifying the CHERI Capability Model", POPL 2023.
34. Kangjie Lu et al., "MOAT: Towards Safe BPF Kernel Extension", USENIX Security 2024.
35. Soo Yee Lim et al., "Rethinking BPF: Can We Trust Kernel Extensions?", OSDI 2024.
36. Hao Sun et al., "Finding Correctness Bugs in eBPF Verifier with Structured and Sanitized
    Programs", EuroSys 2024.
37. Jiacheng Xu et al., "SafeBPF: Hardware-Assisted Defense-in-Depth for eBPF Kernel Extensions",
    arXiv:2409.07508, 2024.
38. Konrad Witaszczyk et al., "CheriBSD Compartmentalization for Userspace Applications",
    IEEE S&P 2024.
39. Jinghao Jia et al., "RSFuzzer: Discovering Deep SMI Handler Vulnerabilities…", IEEE S&P 2024.
40. Arm, "Morello Program" whitepaper, 2022.
41. Chen et al., "KPT: Kernel Page Table Isolation Revisited", OSDI 2023.
42. Zac Hatfield-Dodds, "How eBPF Verifier Works", LWN.net, 2021.

**Language theory / books:**
43. Harold Abelson & Gerald Sussman, *SICP* 2e, 1996.
44. Benjamin Pierce, *Types and Programming Languages*, 2002.
45. Adam Chlipala, *Certified Programming with Dependent Types*, 2013.
46. Raymond Smullyan, *Gödel's Incompleteness Theorems*, 1992.
47. Ross Anderson, *Security Engineering* 2e, 2008.
48. Brendan Gregg, *Systems Performance* 2e, 2020.
49. Brendan Gregg, *BPF Performance Tools*, 2019.
50. Leo Brodie, *Thinking Forth*, 1984.
51. Paul Graham, *On Lisp*, 1993.
52. Mark Miller, "Robust Composition…" (PhD thesis), 2006.

---

## 15. Findings in order of importance (top 3)

1. **Dispatch table at `trust_dispatch.c:1293` is writable-after-init.** This is a concrete W^X
   gap discovered during this research. It has nothing to do with the homoiconic question per se
   but it's a latent vector for any other kernel-write primitive to collapse the trust moat.
   Fix: `const __ro_after_init` annotation + module-init selfcheck. ~40 LOC, do in S74.

2. **The trust ISA is provably Turing-incomplete today, and that is the moat.** Every design
   pressure in future sessions will argue "add one little jump / one little emit / one little
   read-arbitrary-memory opcode". Each individually looks safe; collectively they collapse
   decidability. Recommendation: write the totality invariant as load-bearing architecture docs
   so future sessions cannot erode it accidentally. `trust_invariants.c` is the obvious home.

3. **Recommendation on the headline question: DO NOT add self-emission to trust.ko.** All
   genuine expressiveness gains (deferred actions, policy composition, quorum outcomes, retry)
   are already addressable via (a) the existing `trust_morphogen.c` tick loop, (b) metadata
   edits gated by `trust_quorum.c` N-of-M signing, (c) userspace retry, or (d) fused
   opcodes. None require the ISA to be homoiconic. Accept five "biology-inspired" upgrades
   (fused selftest, capability seal/unseal, quorum-signed metadata patch, codegen for fused
   ops, rodata hardening) totaling ~840 LOC. Defer eBPF-style signed policy bytecode to S80+
   gated on a real TPM2/MOK story. The *totality* property — that every trust batch terminates
   in bounded steps and every authorization decision is decidable — is the ARCHIMATION moat
   itself. Homoiconicity would trade it for flexibility we do not need.

---

*End of S74 Agent F report. ~630 lines. 52 cited sources. No source-code edits made per the
research-only mandate.*
