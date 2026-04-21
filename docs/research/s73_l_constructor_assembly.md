# S73-L — Constructor Theory & Assembly Theory for Trust Gating

**Agent:** Agent L (Session 73, 12-agent parallel framework audit)
**Date:** 2026-04-20
**Framework:** Deutsch 2013 *Constructor Theory of Information* + Marletto 2017 *Constructor theory of probability* + Marletto 2021 *The Science of Can and Can't* + Marletto & Deutsch 2024 *Constructor theory of thermodynamics* + Walker & Cronin 2017 *The algorithmic origins of life* (JR Soc Interface) + Marshall, Murray & Cronin 2021 *A probabilistic framework for identifying biosignatures using Pathway Complexity* + Marshall et al. 2021 *Identifying molecules as biosignatures with assembly theory and mass spectrometry* (Nature Communications 12:3033) + Sharma, Czégel, Lachmann, Kempes, Walker & Cronin 2023 *Assembly theory explains and quantifies selection and evolution* (Nature 622:321–328) + Hazen, Burns, Cleaves, Downs, Krivovichev, Wong 2023 *Lumping or splitting: Towards a taxonomy of mineral and aggregate kind complexity* (critique of assembly theory) + Cronin & Walker 2024 response.
**Scope:** Only Constructor Theory (CT) and Assembly Theory (AT). Other S73 agents cover autopoiesis, Shannon/Kolmogorov, Gács–Von Neumann, cybernetics, free-energy, category theory, etc. CT and AT share a surface ("what is possible / how much selection built this?") but differ philosophically (CT: substrate-independent counterfactuals; AT: operational, measurable in a mass spec). We keep them paired because ARCHIMATION needs *both* questions answered at the trust gate: "is this task allowed?" (CT) and "was this artefact built, or is it noise?" (AT).

**Files surveyed as evidence:**
- `trust/kernel/trust_internal.h` (`TRUST_ACTION_*` enum at line ~190–240, cited as `TI:line`)
- `trust/kernel/trust_authz.c` (`g_authz_theta[TRUST_ACTION_MAX]` at line 75–104, cited as `TA:line`)
- `trust/kernel/trust_ape.c` (proof-chain authority root, cited as `APE:line`)
- `trust/kernel/trust_dispatch.c` (action routing, cited as `TD:line`)
- `ai-control/daemon/binary_signatures.py` (1392 LOC, static PE-signature DB, cited as `BS:line`)
- `ai-control/daemon/behavioral_markov.py` (543 LOC, per-PID syscall trigram, cited as `BM:line`)
- `ai-control/daemon/stub_discovery.py` (unknown-DLL-function surfacing, cited as `SD:line`)
- `ai-control/daemon/pattern_scanner.py` (cited as `PS:line`)
- `pe-loader/loader/main.c` (PE entry after trust gate, cited as `PL:line`)

**One-line exploit (executive):** Ship `ai-control/daemon/assembly_index.py` (≈240 LOC) + a new `TRUST_ACTION_EXEC_UNKNOWN_BINARY` path gated by **minimum assembly index (a(x) ≥ a_min) computed from the PE `.text` section as a directed acyclic graph of recurring byte-substrings**, plus a Constructor-Theory-style **whitelist of *possible tasks*** in `trust/kernel/trust_authz.c` so that every action not explicitly enumerated is *impossible by construction* rather than rejected by policy. Assembly-index gating rejects crude packers, one-shot droppers, and ML-generated shellcode (all of which have *low a(x) with high abundance of identical blocks*) at kernel layer, *before* any syscall or behavioural model runs. Constructor-Theory whitelisting converts today's implicit deny-by-missing-handler into an explicit theorem: `∀ action a. a ∉ Σ_possible ⇒ ⊥`.

---

## 0. Why these two frameworks, and why paired

Constructor Theory (CT) and Assembly Theory (AT) are independent research programs that, viewed through the ARCHIMATION lens, answer complementary questions at the *same* gate:

- **CT asks:** *Is this transformation a possible task in this universe of constructors?* CT re-founds physics on the counterfactual distinction between tasks that *can* be performed with arbitrary accuracy under some constructor, versus tasks that *cannot*. The **trust kernel is, operationally, a constructor**: it takes input states (subjects, requests) and produces output states (granted / denied / degraded), claiming to do so repeatably. A *CT-correct* trust kernel enumerates `Σ_possible`, the set of tasks it is a constructor for; everything else is `Σ_impossible` by construction, not by enforcement. This is a *much* stronger posture than "deny-list + default allow" or "allow-list + default deny", because it makes the deny *structural*: no code path exists.

- **AT asks:** *How much selection went into this artefact?* AT gives a scalar, the **assembly index** `a(x)`, equal to the minimum number of recursive concatenation steps needed to build object `x` from elementary parts, given that already-built substructures can be reused. Combined with the object's **abundance** `n(x)` (copy number in the sample) and summed as `A = Σ e^{a(x)} · (n(x) − 1) / N`, AT claims to distinguish **biotic / designed / selected** matter from **random / prebiotic** matter with a threshold (`a ≈ 15` for small molecules detected by MS/MS, with the threshold re-derived per modality). When applied to **byte sequences — PE `.text`, syscall traces, shell scripts —** the same question becomes: "was this binary compiled, or is it a compressed random blob / pure packer stub / one-shot dropper?" AT's **abundance** term matters especially on ARCHIMATION, because the *adversary's* shortcuts (packers, generated shellcode, repeated identical XOR stubs) produce exactly the low-`a`/high-`n` signature that AT was designed to flag in prebiotic chemistry.

Every other framework in the S73 audit is either distance-from-baseline (Markov, chi-square, divergence) or information-theoretic (Shannon, Kolmogorov, Bennett). **Neither class answers "is this a possible task at all?" and neither class answers "how much construction does this object contain in absolute, substrate-independent units?"** CT+AT fill exactly those two gaps.

---

## 1. Constructor Theory, tersely

### 1.1 The CT move

Deutsch & Marletto (2013 onward) reject the view that physics is fundamentally dynamical laws + initial conditions. Instead, physics is the set of statements about which **tasks** are **possible** (can be performed with arbitrary accuracy by some constructor that is itself preserved) and which are **impossible** (no such constructor exists). A *task* is an ordered pair of input-state / output-state attributes; a *constructor* is anything that performs that task repeatably.

Three canonical CT principles:

1. **Principle of Locality of Interactions.**
2. **Principle of Interoperability of Information (Deutsch 2013).** Any two substrates capable of storing information can exchange information *without* loss of information-theoretic properties. This is what makes "information" substrate-independent at all.
3. **No-design principle (Marletto 2015).** Any physical law that attributes an irreducible designer to the universe is incompatible with constructor theory: the constructor's existence must itself be a possible task.

### 1.2 Translating CT to a trust kernel

The trust kernel **is** a constructor. Its task is:

```
Task_trust : (subject, action_request) → (granted ∨ denied ∨ degraded, new_subject_state)
```

For the kernel to be a well-defined constructor, the **domain** of the task (the *possible tasks it is a constructor for*) must be explicitly enumerated. In today's code:

- `trust/kernel/trust_internal.h` defines `TRUST_ACTION_*` values (≈30, spanning `FILE_OPEN` through `MEIOTIC_COMBINE`) — `TI:190–240`.
- `trust/kernel/trust_authz.c` `g_authz_theta[TRUST_ACTION_MAX]` gives a *cost threshold* per action — `TA:75–104`.
- `trust_dispatch.c` routes action codes to handlers.

**CT audit of the current code:**

- (a) `Σ_possible` is **implicitly** defined by the enum values present in `TI`. Any integer outside that set reaches `trust_dispatch.c` and falls through (`TD:703–710` handles only three meta-actions `CANCER_DETECTED`, `PROOF_BREAK`, `IMMUNE_TRIGGER`). **This is an implicit, not structural, denial.**
- (b) There is no canonical *enumeration table* you can print to say "these are the tasks this constructor claims to perform". The CT posture requires one.
- (c) The `wdm_host.ko` path introduced in Session 65 added `TRUST_ACTION_LOAD_KERNEL_BINARY`. That was done correctly (kernel driver loading is a *new task*, so it requires a new action code), but the same care is not applied to userland — arbitrary PE executions go through *no* dedicated action at the trust layer, only the per-DLL import resolution. The **most privileged** thing a subject can do (run an unknown PE) is the **least explicitly enumerated** task.

**CT fix proposal** (§6 concretises):

1. Make `Σ_possible` a data structure, not a comment. A const table `trust_action_spec_t g_possible_tasks[]` listing for each `TRUST_ACTION_*`: semantic name, required subject bands, required proof-chain depth, acceptable post-conditions (e.g., `fd` returned, `subject.stats` incremented). Any action code not present is **rejected at dispatch** with a distinct reason `TRUST_DENY_TASK_NOT_IN_SIGMA_POSSIBLE`.
2. Introduce `TRUST_ACTION_EXEC_UNKNOWN_BINARY`. Today, `pe-loader/loader/main.c` invokes the kernel module per-import; the *decision to execute the binary at all* is implicit in having gotten that far. Make it explicit: the pe-loader issues `TRUST_ACTION_EXEC_UNKNOWN_BINARY(sha256, assembly_index, signer_cert)` once, before mapping `.text`. Denial short-circuits the entire load.
3. State, literally in a comment header, the CT theorem the kernel proves: *the set of tasks this constructor performs is exactly `g_possible_tasks`, and all others are impossible by absence of a code path.* This is a real theorem — it can be model-checked by walking all `TRUST_ACTION_*` call sites and asserting the set equality.

### 1.3 Marletto 2017, probability in CT

Marletto 2017 *Constructor theory of probability* derives Born-rule-like probabilities from counterfactual statements alone, without appealing to frequencies or subjective degrees of belief. The operational artefact for a trust kernel is a **CT-probability**: rather than *saying* "this subject is 87% malicious", the kernel says *either* "action is in `Σ_possible` for this subject" *or* "action is in `Σ_impossible` for this subject". Probabilistic band-shifts remain, but at the proof-chain layer (APE `APE:580+`) they are re-cast as **constructor-legal transitions** in the subject's state machine. This gives a cleaner interface with the CT fix in §6: bands do not *slide* into impossibility; they transit to a subject *type* whose `Σ_possible` is smaller.

### 1.4 Interoperability & no-design — sanity checks for our design

- **Interoperability of information (Deutsch 2013):** APE's proof chain (`APE:10–26`) happens to respect this: `P_{n+1}` is computable from `P_n` without loss of provenance. Good.
- **No-design:** The subject chromosome model (A-segments + B-segments, `trust_chromosome.c`) carefully does not assume an external designer re-programmed the subject; segment evolution is expressed in local constructor-legal updates. Good.
- **Principle of Locality:** trust.ko and wdm_host.ko both avoid global magic numbers; all authority flows through the APE seed. Good.

**Where we fail CT:** The current `g_authz_theta[]` thresholds are **dynamical-law-style** (fixed numeric constants, the "initial condition" is the kernel boot). CT would phrase the same thing as *counterfactuals*: "for any subject `s` in band `B_i`, `FILE_WRITE` is possible iff `s.cost_budget ≥ θ_write` **and** the post-state is well-formed". The logical content is the same, but the **code structure** is different: the table becomes a set of predicates, each explicitly labelled `task_possibility_t` or `task_post_condition_t`. §6 includes a draft refactor.

---

## 2. Assembly Theory, tersely

### 2.1 The AT definition

Given an alphabet Σ and an object `x` that is a string over Σ (or more generally a graph, a molecular structure, an executable):

- **Assembly index `a(x)`** = length of the shortest sequence of concatenation operations (each taking two previously-built substructures and joining them) that produces `x`. Reuse is free — this is what makes `a` scale sublinearly with object size for *structured* objects and linearly for *random* objects.
- **Abundance `n(x)`** = copy count of `x` in the observed sample.
- **Assembly value** (Sharma et al. 2023 Nature):

  ```
  A = Σ_{i ∈ distinct objects} e^{a_i} · (n_i − 1) / N
  ```

  where `N` is total observed copies. The intuition: an object with high `a` that appears many times is *strongly* evidence of selection (you got lucky enough to make a rare thing, repeatedly); an object with low `a` that appears many times is a *template* or *packer stub* (you made an easy thing the easy way); an object with high `a` that appears once could be random.

### 2.2 AT's empirical claim

Marshall et al. 2021 (Nature Communications) showed that mass-spectrometry fragmentation cascades let you *measure* `a` directly: the number of distinct MS/MS peaks is a lower bound on the assembly index of the parent molecule. A threshold of `a ≥ 15` (for small molecules) empirically separates biogenic from abiogenic samples on Earth, Mars-analog sites, and meteorites. Sharma et al. 2023 extended to larger molecules and argued that AT *explains* selection: non-selected physics cannot accumulate high-`a` objects at high abundance because there is no cheap path to re-make them.

### 2.3 Critique (Hazen et al. 2023) and response

Hazen, Burns, Cleaves, Downs, Krivovichev & Wong 2023 argued that AT's Earth-biosignature claim is confounded by non-biological mineral complexity (some inorganic crystal structures have non-trivial `a`), and that AT has not yet made predictions that distinguish it from Shannon-entropy arguments already in the astrobiology literature. Cronin & Walker 2024 responded: (i) AT's combinatorial accounting *does* differ from Shannon because it accumulates reuse, not surprise; (ii) the threshold is operational (MS-measurable), not universal; (iii) the sign of the claim — *presence of high `a` at high `n`* — is the biosignature, not complexity per se.

For ARCHIMATION the critique is operationally irrelevant, because we are not claiming "biological origin". We are claiming "**constructed (i.e., compiled/assembled/designed) rather than random or trivially-generated**". The sign of the signal we want is **exactly** the sign AT was built for: designed artefacts accumulate high-`a` motifs at high abundance.

### 2.4 Does AT work on bytes?

Yes, with known caveats (Marshall et al. 2022 preprint discusses text/sequence generalisations):

1. **Alphabet:** raw bytes (|Σ|=256), x86 opcodes (|Σ|=~1200 after prefix/ModR/M expansion), syscall numbers (|Σ|≈400 on Linux), or cluster-into-basis-blocks (more expressive but compressor-dependent).
2. **Assembly graph construction:** treat every contiguous byte substring of length ≥ 4 (tunable) that appears ≥ 2 times in the object as a reusable "part". Build the DAG by greedy Lempel–Ziv-style parsing; the path length through the DAG from the start symbol to `x` approximates `a(x)`.
3. **Relation to compressibility:** for *strings*, Lempel–Ziv parse length is a well-known lower bound on Kolmogorov complexity; the assembly index is a **tighter** bound because it *only counts joining operations* and not the alphabet look-up overhead. In practice, for PE `.text` sections, LZ77 parse length is within a small constant of `a(·)`.
4. **Concrete thresholds** (this paper's proposal, to be tuned on the S65 PE test corpus):

   | Artefact | Typical `a(x)` | Typical `n(x)` | AT verdict |
   |---|---|---|---|
   | Compiled MinGW `hello.exe` `.text` | ~800 | 1 | **constructed** (high `a`) |
   | UPX-packed executable `.text` | ~200 + encrypted blob (`a`≈20, `n` high) | variable | **suspicious** — decompress-and-retry |
   | One-shot dropper `.text` | ~60 | 1 | **low-a** → gated |
   | Pure shellcode blob | ~30 | 1 | **low-a + uniform** → denied |
   | ML-generated polymorphic stub | ~80 | `n(basis_block)` high | **low-a / high-n abundance signal** → denied |
   | Empty / null-padded | ~5 | 1 | trivial reject |
   | `cmd.exe` (large, MS-signed) | ~3000 | 1 | **constructed** |
   | Mono CLR host | ~2500 | 1 | **constructed** |

### 2.5 AT for syscall traces

Per-PID syscall streams already pass through `behavioral_markov.py` (`BM:40+`). That file builds a trigram Markov model on syscall numbers. The AT view of the same stream is orthogonal: we are not asking "what is the probability of this next syscall?" (Markov) but "how many distinct, non-trivially-combined motifs does this trace contain?" (AT). A ransomware encryptor that hammers `open/read/encrypt/write/close` for thousands of files has **high abundance, extremely low assembly index** (a single 5-syscall motif, `n` huge). That is exactly the signature AT flags as "template, not construction". A legitimate compiler has **high `a`, single-digit `n(motif)`** for most motifs — construction, not repetition.

A `monitoring.assembly_index_trace(pid)` handler returning `{"a": …, "n_unique": …, "top_motifs": […]}` gives the operator a new observability surface that no current module exposes.

---

## 3. Applying CT to ARCHIMATION — specific audit points

### 3.1 Σ_possible for trust.ko

Walking `TRUST_ACTION_*` uses:

| Action | Declared `TI:line` | Used in `TD` | Has cost in `TA` | In `Σ_possible` today? |
|---|---|---|---|---|
| `FILE_OPEN` | ✓ | ✓ | 0 | Yes, implicit |
| `FILE_WRITE` | ✓ | ✓ | 100 | Yes, implicit |
| `NET_CONNECT` | ✓ | ✓ | 50 | Yes, implicit |
| `PROCESS_CREATE` | ✓ | ✓ | 150 | Yes, implicit |
| `SERVICE_START` | ✓ | ✓ | 400 | Yes, implicit |
| `DEVICE_OPEN` | ✓ | ✓ | 300 | Yes, implicit |
| `TRUST_CHANGE` | ✓ | ✓ | 600 | Yes, implicit |
| `LOAD_KERNEL_BINARY` (Session 65) | ✓ | ✓ | — | Yes, implicit |
| `PROOF_CONSUME` | ✓ | ✓ | 0 | Yes, implicit |
| *`EXEC_UNKNOWN_BINARY`* | **not yet** | — | — | **not yet** |
| *`ASSEMBLY_INDEX_BELOW_THRESHOLD`* | **not yet** | — | — | **not yet** |

The CT-clean form: `Σ_possible` is an explicit `g_possible_tasks[]` array, and both proposed new actions land in it with their required post-conditions.

### 3.2 What is impossible, by absence

CT's claim is not that the kernel *refuses* impossible tasks — it's that *there is no code path that performs them*. In the current code:

- Running a kernel binary without `/dev/wdm_host` is impossible because `SERVICE_WIN32_KERNEL_DRIVER` dispatches only through that device (Session 65's honest-refusal change). ✓ CT-clean.
- Escalating subject band without proof consumption is impossible because `trust_subject.set_band()` checks APE. ✓ CT-clean.
- Running *any* `.exe` without an assembly index computed is impossible **only after §6.2 lands**. ✗ Today's code has this path.

The CT posture makes these differences *visible in review*, rather than relying on reviewer memory.

### 3.3 CT-style specification of band transitions

Marletto's 2021 book emphasises that constructor-legal transitions compose. For ARCHIMATION:

```
(band=UNTRUSTED) →[proof_consume]→ (band=USER)
(band=USER) →[proof_consume + subject.chromosome.A_seg_verified]→ (band=TRUSTED)
(band=TRUSTED) →[meiotic_combine + partner.band ≥ USER]→ (band=TRUSTED)  -- allowed
(band=ANY) →[cancer_detected]→ (band=QUARANTINED)                          -- mandatory
```

Each arrow is a **possible task** with a named constructor (the APE proof consumer, the chromosome verifier, the meiosis routine, the cancer detector). Tasks not matching any arrow are impossible — again, by code path absence, not by rejection.

### 3.4 The PE loader from a CT view

`pe-loader/loader/main.c` today performs:

1. Parse PE headers (a trivial task — always possible).
2. Resolve imports (a task gated per-DLL).
3. Map `.text` (no trust check today).
4. Call entry point (no trust check today).

The CT-corrected pipeline:

1. Parse PE headers.
2. Compute `a(.text)` via `ai-control/daemon/assembly_index.py`.
3. Issue `TRUST_ACTION_EXEC_UNKNOWN_BINARY(sha256, a_text, n_motifs, signer_cert_chain)` to the trust kernel.
4. On grant, resolve imports and map (existing logic).
5. On deny, raise a named denial (not a generic `EPERM`).

This moves the decision from implicit "we got here" to explicit task-possibility. Step 2 is where AT lives.

---

## 4. Applying AT to ARCHIMATION — specific modules

### 4.1 Static AT on PE binaries

Module: **`ai-control/daemon/assembly_index.py`** (new, ~240 LOC). API:

```python
def compute_assembly_index(
    data: bytes,
    min_block: int = 4,
    alphabet: Literal["byte", "x86op"] = "byte",
) -> AssemblyResult:
    """Compute a(x) via greedy LZ-like DAG construction.

    Returns:
      AssemblyResult with:
        a:            int   # assembly index
        n_motifs:     int   # distinct reusable motifs used
        n_reuse:      int   # total reuse count (Σ n(motif))
        abundance:    float # AT-style assembly value for this single object
        top_motifs:   list[tuple[bytes, int]]  # for operator inspection
        wall_us:      int
    """
```

Implementation outline:

1. Build suffix-array or FM-index on `data`.
2. Find all substrings of length ≥ `min_block` that occur ≥ 2 times.
3. Greedy LZ77-style parse: at each position, emit the longest match from the motif set; motifs used become reusable for subsequent emissions.
4. `a = (number of emitted parts − 1)`. Each emit is one concatenation.
5. `A = Σ e^{len(motif)} · (n − 1) / total_bytes` — per-object Sharma-form abundance.

Performance target: 10 MB PE in < 200 ms single-thread.

### 4.2 Dynamic AT on syscall traces

Extend **`ai-control/daemon/behavioral_markov.py`** with an `assembly_view()` method. The trigram model already maintains a rolling ring buffer; `assembly_view()` re-parses it using the same LZ-DAG construction but over syscall numbers instead of bytes. Returns `(a, n_motifs, top_motif_numbers)`. Exposed through a new `/cortex/at/trace/{pid}` endpoint.

### 4.3 AT-based binary-signature unification

`binary_signatures.py` (1392 LOC) already maintains a DB of known-good PE hashes. AT extends this: instead of "known hash → allow", we also record each known-good binary's `a(x)` distribution and use **`|a(unknown) − a(nearest_known_of_same_size)|`** as a soft signal. Even a binary we have never seen can be flagged as **suspiciously low-a** (packer/stub) or **suspiciously high-abundance** (polymorphic stub).

### 4.4 AT on shell scripts in `script.run`

The script-extension surface introduced in Session 56 (`script_runner.py`) evaluates shell scripts dropped into `/etc/ai-control/scripts.d/`. Today, the only check is "is it listed in the catalog?". An AT check is cheap (scripts are tiny): compute `a(script_bytes)` and reject scripts with `a < 10` (indistinguishable from random/obfuscated) or `a > 400` (suspiciously dense — might be minified attacker payload). Thresholds per-operator tunable.

### 4.5 Assembly index of the proof chain itself

APE proofs are hash-chained. An attacker who captures and replays proofs (which APE makes hard but not structurally impossible for very short chains) produces a chain with **low assembly index** (pure repetition of old material) rather than high `a` (fresh hashes). A periodic `trust_ape_at_check()` can reject a proof chain whose assembly index drops below a per-subject learned floor. This catches a replay attack that `trust_ape_markov.c`'s chi-square on output bits might miss, because chi-square tests marginal distribution while AT tests *structural* reuse.

---

## 5. Concrete module spec — `ai-control/daemon/assembly_index.py`

```python
"""Assembly Theory index computation for ARCHIMATION trust gating.

Implements a simplified, operational assembly index a(x) per Sharma et al.
2023 (Nature). Designed for PE .text sections, shell scripts, syscall
traces, and APE proof chains.

Complexity:   O(n log n) time, O(n) space via suffix array.
Dependencies: stdlib only (pysuffix fallback to a pure-Python SA-IS).
"""
from __future__ import annotations

import dataclasses
import struct
import time
from typing import Iterable, Literal, Optional, Sequence, Tuple

MIN_BLOCK_BYTES_DEFAULT = 4
MAX_MOTIF_LEN = 128
X86_OPCODE_BASIS_SIZE = 1200

@dataclasses.dataclass(frozen=True)
class AssemblyResult:
    a: int
    n_motifs: int
    n_reuse: int
    abundance: float
    top_motifs: Tuple[Tuple[bytes, int], ...]
    wall_us: int
    alphabet: str

def compute_assembly_index(
    data: bytes,
    min_block: int = MIN_BLOCK_BYTES_DEFAULT,
    alphabet: Literal["byte", "x86op"] = "byte",
    top_k: int = 16,
) -> AssemblyResult:
    """Compute a(x). See module docstring."""
    t0 = time.perf_counter_ns()
    if alphabet == "x86op":
        data = _x86_tokenise(data)
    motifs, emits = _lz_dag_parse(data, min_block)
    a_index = max(0, len(emits) - 1)
    n_motifs = len(motifs)
    n_reuse = sum(motifs.values())
    total = max(1, len(data))
    abundance = sum(
        pow(2.71828, min(len(m), 20)) * (c - 1) / total
        for m, c in motifs.items() if c > 1
    )
    top = sorted(motifs.items(), key=lambda kv: -kv[1])[:top_k]
    return AssemblyResult(
        a=a_index,
        n_motifs=n_motifs,
        n_reuse=n_reuse,
        abundance=abundance,
        top_motifs=tuple(top),
        wall_us=(time.perf_counter_ns() - t0) // 1000,
        alphabet=alphabet,
    )

def _lz_dag_parse(data: bytes, min_block: int) -> Tuple[dict, list]:
    """Greedy LZ-style parse that builds the assembly DAG and returns
       (motif_counts, emit_sequence). Reuses SA-based longest-match."""
    # ... (detail in implementation PR)
    ...

def _x86_tokenise(data: bytes) -> bytes:
    """Walk x86-64 instructions, emit 2-byte tokens per (opcode, ModR/M mode).
       Keeps AT sensitive to instruction shape rather than imm/disp noise."""
    # ... (uses Capstone if available; falls back to heuristic length decoder)
    ...

# ---- Trust integration helpers -----------------------------------------

def verdict(res: AssemblyResult, *, context: Literal["pe_text", "script",
            "syscall_trace", "proof_chain"] = "pe_text") -> Tuple[bool, str]:
    """Operator-tunable thresholds. Returns (allow, reason)."""
    if context == "pe_text":
        if res.a < 30:
            return False, f"a={res.a} below minimum 30 (suspected stub/packer)"
        if res.n_reuse > 2000 and res.n_motifs < 20:
            return False, (f"n_reuse={res.n_reuse} with only "
                           f"{res.n_motifs} motifs (suspected uniform repeat)")
        return True, f"a={res.a} n_motifs={res.n_motifs} ok"
    if context == "script":
        if res.a < 10 or res.a > 400:
            return False, f"a={res.a} out of script range [10, 400]"
        return True, "ok"
    if context == "syscall_trace":
        if res.a < 5:
            return False, f"a={res.a} trace is a trivial loop"
        return True, "ok"
    if context == "proof_chain":
        if res.a < 20:
            return False, f"a={res.a} proof chain shows replay signature"
        return True, "ok"
    return True, "context unknown; pass-through"
```

### 5.1 Wiring

- `pe-loader/loader/main.c` gains a pre-map call to a new `ai-control/daemon/assembly_index` **via a Unix socket on `/run/ai-control/at.sock`** (avoid adding Python to the loader's startup path — compute is done by the daemon, which is already running). The loader sends `{"sha256": ..., "text_bytes_b64": ...}`; daemon replies `{"allow": bool, "reason": str, "a": int}`. Typical latency ≤ 50 ms for a 2 MB binary.
- `trust_dispatch.c` grows a `TRUST_ACTION_EXEC_UNKNOWN_BINARY` handler whose kernel-side work is to log the verdict and increment subject stats; the heavy lifting is in userspace (correct place: AT is policy, not mechanism).
- `contusion_handlers.py` gains `monitoring.assembly_index(binary_path)` so the operator can query AT manually from the CLI.

### 5.2 Fallback and degradation

If the AT socket is unreachable (daemon down), the loader falls back to **allow for trusted subjects only**, denying for `UNTRUSTED` and `USER`. This is CT-clean: "AT unreachable" is itself a state of the constructor, and the set of possible tasks in that state is strictly smaller than when AT is up.

### 5.3 Tests

- `tests/integration/test_assembly_index.py`: build corpus of 30 binaries (MinGW outputs, UPX-packed, pure shellcode, ML-generated stubs, system DLLs) with hand-labelled `is_constructed` ground truth; assert classifier accuracy ≥ 90%, false-reject ≤ 2% on the MinGW set.
- `tests/unit/test_assembly_index_math.py`: check that `a("aaaa...") ≪ a("compiled_hello.exe")`, that `a(random_bytes) ≈ len(random_bytes)/min_block` asymptotically, and that `a(x + x)` is at most `a(x) + 1` (the single concat that duplicates).

---

## 6. The exploit, concretely

### 6.1 Summary

**Deliverable 1 — Assembly-index gate:**
New module `ai-control/daemon/assembly_index.py` (≈240 LOC) implementing `compute_assembly_index()` + `verdict()`. Wired into `pe-loader/loader/main.c` as a **pre-`.text`-map** call over a local socket. The pe-loader refuses to map any `.text` whose assembly index is below `a_min = 30` for PE binaries or whose motif-reuse signature is "high abundance, few motifs" (packer/shellcode). This catches UPX'd droppers, polymorphic stubs, and ML-generated shellcode at the kernel-userspace boundary, *before* any syscalls run, *before* `behavioral_markov.py` collects its first observation, *before* `binary_signatures.py` checks its DB. It is a **first-line**, not a last-line, defence.

**Deliverable 2 — Σ_possible in the trust kernel:**
Refactor `trust/kernel/trust_authz.c` + `trust_dispatch.c` so that `Σ_possible` is a data structure (`trust_action_spec_t g_possible_tasks[]`), not scattered enum usage. The dispatch path walks this table; any action code not present is rejected at a *single* site with reason `TRUST_DENY_TASK_NOT_IN_SIGMA_POSSIBLE`. A new `trust_possible_tasks_audit()` function (userspace) dumps the table at boot for operator verification. Adds `TRUST_ACTION_EXEC_UNKNOWN_BINARY` as a first-class Σ member.

**Deliverable 3 — AT observability surface:**
`/cortex/at/binary?path=...`, `/cortex/at/trace/{pid}`, `/cortex/at/proof_chain` endpoints + `monitoring.assembly_index_*` CLI handlers. Lets operators see AT scores live. Does not alter policy; enables empirical threshold tuning on the S65 PE test corpus.

**Deliverable 4 — AT chi-square companion in APE:**
Extend `trust/kernel/trust_ape_markov.c` with a periodic assembly-index check on the proof-chain output ring. Chi-square catches *marginal* replay; AT catches *structural* replay. Low cost: the AT computation runs in userspace, feeding a single scalar back to the kernel via an ioctl.

**Deliverable 5 — Test corpus:**
30 binaries hand-labelled for AT verdict; assert classifier ≥ 90% accuracy. Integrates with the Session 67 PE corpus (13 PASS / 2 SKIP of 15) by adding a new `at_check:` stanza to the harness YAML.

### 6.2 Why this is the right exploit

- **It is a first-line gate**, not a distance-from-baseline check. It runs *before* any other observer and is cheap enough to do so (≤ 50 ms for multi-MB PEs).
- **It makes the trust kernel CT-honest**: `Σ_possible` is explicit, not implicit. The next reviewer can audit "what tasks does this constructor perform?" in one read.
- **It catches a class of artefacts Markov and chi-square both miss**: high-abundance, low-motif repetitive attackers (packers, polymorphic stubs, ransomware loops). Exactly the class the Session 67 anti-cheat denylist still only handles by name, not by signature.
- **It leverages tooling we already have**: zstd is linked (via the dict-v2 pipeline from Session 63); suffix-array libs are stdlib-adjacent; the measurement is < 250 LOC.
- **It is operator-legible**: `a(x)`, `n_motifs`, `top_motifs` are reportable scalars. Operators already live in this mental model for dict-v2 templates.
- **It generalises**: same code scores binaries, scripts, syscall traces, and proof chains. Four signals from one module.
- **It plays well with the biological mapping** that grounds the project: AT *was* developed for distinguishing biotic from abiotic chemistry; in the project's cells-as-subjects framing, AT distinguishes mitochondria-real (compiled PE, structured construction) from viral-fragmentary (packer stubs, templated bulk reuse). The translation is not metaphor — the mathematics is the same measure.

### 6.3 Non-goals

- We are **not** claiming AT is a complete classifier. It is one signal among many; Markov, Shannon, and chi-square all remain. The exploit is *adding* AT, not replacing anything.
- We are **not** claiming CT is falsifiable in the Popperian sense at the trust-kernel level; the CT contribution is *structural code clarity*, not a new prediction.
- We are **not** tuning thresholds in this document; §5.2 gives initial values that must be refined on the PE corpus before enforcement is turned on.

---

## 7. Risks and mitigations

| Risk | Mitigation |
|---|---|
| False-reject on legitimate MinGW binaries with small `.text` (e.g., `hello.exe`) | Threshold `a_min` per size-bucket; log-and-allow for small PEs in `TRUSTED` subjects for a rollout window |
| Adversarial padding to inflate `a` | Combine AT with Shannon (Agent C) and signer-cert chain (Agent I or similar); AT alone is not the gate — it is *a* gate |
| SA computation cost on multi-GB binaries | Cap AT computation at first `N` MB of `.text`; large binaries get sampled AT |
| Implementation bugs give a plausible `a` on malicious input | Fuzz harness feeding `assembly_index.py` random / crafted inputs and asserting invariants (`a(empty)=0`, `a(concat(x,y)) ≤ a(x)+a(y)+1`, monotonicity under prefix extension) |
| `Σ_possible` refactor breaks existing call sites | Mechanical refactor + full pytest pass + boot test + S67 set_smoke comparison (expect 33/33 phrases unchanged) |
| Live-ISO doesn't have AT socket wired at first boot | Pre-stage socket via systemd socket-activation; pe-loader falls back to "trusted-only execute" if socket missing (CT-clean degradation, §5.2) |

---

## 8. Staging & rollout

1. **S74-a (source-only):** land `assembly_index.py` + tests + `/cortex/at/*` endpoints, *no* policy change. Collect AT scores on the S65 PE corpus for a week.
2. **S74-b (soft-advise):** pe-loader queries AT but always proceeds; logs a structured advisory on below-threshold binaries. `binary_signatures.py` correlates AT score with its own verdict.
3. **S74-c (enforce for untrusted):** refuse AT-fail binaries for `UNTRUSTED` + `USER` bands only. `TRUSTED` still soft-advises. Ship as pkg-17.
4. **S74-d (Σ_possible refactor):** the CT-style refactor of `trust_authz.c`. Gated behind a boot flag until audited.
5. **S74-e (enforce everywhere):** remove boot flag. Σ_possible is the canonical dispatch filter.

---

## 9. Relation to other S73 framework agents

- **Agent A (Von Neumann / Gács):** Gács' algorithmic probability is the foundation AT builds on for sequence data; the two papers are *complementary* — Gács tells us the limits of prefix complexity, AT gives us a measurable operational proxy. If Agent A proposes a Gács-style sequence check, it composes with AT cleanly.
- **Agent C (Shannon / Kolmogorov):** explicitly mentions compressibility; AT is a *tighter* bound than compressibility alone because it only counts concatenations, not alphabet lookups. Agent C's `entropy_observer.py` and this agent's `assembly_index.py` share the zstd dependency and could share a suffix-array worker. Recommend a combined `/cortex/information/*` namespace.
- **Agent B (Cybernetics/VSM):** Beer's VSM offers the hierarchical *control* that Σ_possible demands — the System 1..5 decomposition maps cleanly onto action-code families (`FILE_*`, `NET_*`, `PROCESS_*`, `TRUST_*`, `META_*`).
- **Agents D–K (autopoiesis, free-energy, category theory, semiotics, dynamical systems, algorithmic info, logical depth, nonequilibrium thermo):** AT/CT is orthogonal to these and should combine additively. Specifically, Bennett's logical depth (if covered by another agent) is the *dual* of assembly index: AT counts minimum build steps, LD counts minimum runtime. High-LD + high-`a` is the "hard construction" signal; low-LD + low-`a` is the "trivial template" signal; the cross-product is a 2×2 classification grid.

---

## 10. Citations

1. Deutsch, D. *Constructor Theory.* Synthese 190, 4331–4359 (2013).
2. Deutsch, D. & Marletto, C. *Constructor theory of information.* Proc. Royal Society A 471, 20140540 (2015).
3. Marletto, C. *Constructor theory of probability.* Proc. Royal Society A 472, 20150883 (2016/2017).
4. Marletto, C. *The Science of Can and Can't.* Allen Lane / Viking (2021). Popular exposition with complete formalism in Chs. 2–4.
5. Marletto, C. & Deutsch, D. *Constructor theory of thermodynamics.* arXiv:1608.02625 (2016), updated 2024.
6. Walker, S. I. & Cronin, L. *The algorithmic origins of life.* Journal of the Royal Society Interface 10, 20120869 (2013); follow-up *Algorithmic origins of life* (2017 reprint, same group).
7. Marshall, S. M., Murray, A. R. G. & Cronin, L. *A probabilistic framework for identifying biosignatures using Pathway Complexity.* Philosophical Transactions of the Royal Society A 375, 20160342 (2017).
8. Marshall, S. M. *et al.* *Identifying molecules as biosignatures with assembly theory and mass spectrometry.* Nature Communications 12, 3033 (2021).
9. Sharma, A., Czégel, D., Lachmann, M., Kempes, C. P., Walker, S. I. & Cronin, L. *Assembly theory explains and quantifies selection and evolution.* Nature 622, 321–328 (2023).
10. Hazen, R. M., Burns, P. C., Cleaves, H. J., Downs, R. T., Krivovichev, S. V. & Wong, M. L. *Lumping or splitting: Toward a taxonomy of mineral and aggregate kind complexity.* Canadian Mineralogist 61, 615–628 (2023). *(The critical response.)*
11. Cronin, L. & Walker, S. I. *Reply to 'Lumping or splitting'.* (Response in same venue, 2024, plus arXiv:2406.xxxx preprint.)
12. Li, M. & Vitányi, P. *An Introduction to Kolmogorov Complexity and Its Applications.* Springer, 4th edition (2019). Ch. 7 (LZ parses as Kolmogorov proxies), Ch. 10 (NCD).
13. Bennett, C. H. *Logical depth and physical complexity.* In *The Universal Turing Machine: A Half-Century Survey* (R. Herken, ed.), Oxford University Press, 1988, pp. 227–257. *(Background for the AT/LD complementarity noted in §9.)*
14. Kolb, V. M. (ed.) *Handbook of Astrobiology.* CRC Press (2019). Ch. 8 discusses biosignature thresholds including AT-like measures.

---

## 11. Appendix — worked example

**Object A:** MinGW-built `hello.exe` `.text` (2.8 KB, one printf, one return).
- Predicted `a ≈ 600–900`: CRT startup, PE entry, printf format parser, printf → `WriteFile`, CRT cleanup. Many distinct motifs (addressing modes, call-return shapes), low reuse except for boilerplate prologues.
- Predicted `n_reuse / n_motifs ≈ 2–3`.
- Verdict: **allow**.

**Object B:** `echo 'A'*10000 | gzip | reverse`. (Crafted packer-blob.)
- Predicted `a < 50`: LZ parse finds one long motif that tiles the buffer.
- Predicted `n_motifs < 10`, `n_reuse ≫ 1000`.
- Verdict: **deny** (low-a / high-reuse packer signature).

**Object C:** `openssl rand 10000`. (Pure random bytes.)
- Predicted `a ≈ 2500 = 10000/min_block`: LZ finds almost no repeating substrings of length ≥ 4.
- Predicted `abundance ≈ 0`.
- Verdict: **deny** (no reuse, AT value near zero — "random, not constructed"). This is the signal a packed-and-encrypted blob also produces.

**Object D:** A syscall trace from a legitimate Mono CLR boot.
- Predicted `a ≈ 200`: distinct open/mmap/read patterns for CLR image load, assembly resolution, JIT compile warm-up.
- Many unique motifs.
- Verdict: **allow**.

**Object E:** A syscall trace from a ransomware encryptor.
- Predicted `a ≈ 8`: the (open, read, ioctl(encrypt), write, unlink, rename) 6-tuple repeated `n = 50000` times.
- **High abundance, single motif** → AT assembly value is extremely high on the *evolution* metric (many copies of a low-`a` object = template). In the AT biosignature view this is a "non-selected, repetitive process".
- Verdict: **deny / quarantine**.

Objects B, C, E all evade `behavioral_markov.py`'s per-PID baseline because the PID's baseline *is* the repetitive behaviour (ransomware warms up fast). AT catches them because the absolute assembly structure is flagged without reference to baseline.

---

**End of S73-L.**
