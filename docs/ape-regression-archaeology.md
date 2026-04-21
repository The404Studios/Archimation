# APE Reconfigurable-Hash Regression — Git Archaeology

**Session:** S74 Agent S (investigation only, read-only)
**Date:** 2026-04-20
**Companion to:** `docs/ape-regression-triage.md` (Agent K — surface triage)
**Scope:** determine whether `apply_reconfigurable_hash()` / `trust_ape_consume_proof_v2()` / the 94,371,840-configuration reconfigurable hash were ever implemented, or whether the header/paper claims are aspirational scaffolding.

Agent K concluded ASPIRATIONAL from `git log --all` alone. That conclusion is **wrong** — the published-branch history is incomplete because S38-S73 work was squashed into a single checkpoint `5013ad9`. This document uses the git **object store** (dangling commits) plus session memory cross-references to reach a different verdict.

---

## §1 Executive Summary

**Verdict: REGRESSION (not aspirational).**

The `apply_reconfigurable_hash()` function, `trust_ape_consume_proof_v2()`, the 720-entry `ape_perm_table`, and the `BUILD_BUG_ON(APE_CFG_TOTAL != 94371840ULL)` compile-time assertion were all **fully implemented and present in the working tree** on 2026-04-18 and 2026-04-19 (Sessions 48 and 49), then **deleted wholesale** between 2026-04-19 18:40:52 PDT and 2026-04-20 09:48:37 PDT. The deletion never made it into a committed-then-reverted form on master (which is why `git log --all` against master's history misses it); it exists only in four dangling git-stash commits recoverable via `git fsck --lost-found`.

**Evidence chain:**

1. Dangling commit `0c55eec12cc3f9e5e4b4e6036b3ff61f66d3f450` (2026-04-18 23:31:06 PDT, "WIP on master: e2f4ed7") contains `trust/kernel/trust_ape.c` at **1251 LOC** with the full implementation.
2. Dangling commit `9b04ca1948e9772588dda860b1a5e9a58ad08c49` (2026-04-19 18:39:52 PDT) contains `trust_ape.c` at **1260 LOC** (continued growth).
3. Dangling commit `1faee94cee5dae35e25732c486d278cd3f88a22e` (2026-04-20 09:48:37 PDT) contains `trust_ape.c` at **655 LOC** — the current shipping version, with all three references gone.
4. Session memory `session48_10agent_paper_conformance.md:27,59,60` explicitly claims Agent 1 "rewrote trust_ape.c" to implement "reconfigurable hash 94,371,840 configs" and cites `BUILD_BUG_ON(APE_CFG_TOTAL != 94371840ULL)` as ✓.
5. Session memory `session49_5agent_role_taxonomy.md:44` cites `trust_ape.c:1025` as a real call site inside `trust_ape_consume_proof_v2` — a line number only reachable in a >1000-LOC version of the file.
6. Session memory `session50_10agent_production_hardening.md:41` cites Agent I's rewrite of `roa-conformance.md` to use the names `apply_reconfigurable_hash` and `derive_hash_cfg` specifically because they were the **real shipping symbols** at that point.
7. Session memory `session58_10agent_markov_chains.md:22` (Agent A3) comment in `trust_ape_markov.c`: "*We CANNOT call apply_reconfigurable_hash() directly from this translation unit (it is `static` to trust_ape.c, which is locked to Agent 1 of S48)*" — a comment that would have been meaningless if the function didn't exist.

**LOC estimate for bring-back:** the full regression is ~605 LOC (1260 → 655). Bring-back is not guessing what to write; it is restoring from `git show 9b04ca1:trust/kernel/trust_ape.c` (one checkout + glue fixes for post-regression context).

**Paper-submission impact:** the paper claim "94,371,840 configurations" was honest at the time it was written (S48) because the code matched. The regression event broke the paper-vs-code bisimulation and nobody noticed until Research D (S74) did the crypto audit. This is a **restoration** task, not a fabrication task — we are bringing back our own code from our own stash.

---

## §2 Timeline (Dated, From Git Object Store)

All timestamps PDT (UTC-7). Commit SHAs from `git fsck --lost-found`.

| Time (PDT)            | SHA       | `trust_ape.c` LOC | `trust_ape.h` LOC | Has `apply_reconfigurable_hash`? | Has `consume_proof_v2`? | Has `APE_CFG_TOTAL`? | Event                                                                 |
|-----------------------|-----------|-------------------|-------------------|-----------------------------------|--------------------------|----------------------|-----------------------------------------------------------------------|
| 2026-04-13 09:29      | `0408da8` | 465               | —                 | No                                | No                       | No                   | Initial commit: 3-algo SHA/BLAKE2b/SHA3 trust_ape.c. No .h.          |
| 2026-04-14 17:19      | `20a8f86` | 646               | —                 | No                                | No                       | No                   | S30 perf pass: FNV-1a hash index added. Still 3-algo.                |
| 2026-04-18 15:27      | `7fa89b8` | 1137              | 0 (no .h)         | **Yes**                           | **Yes**                  | **Yes**              | S48 mid-flight stash. 720-perm table + reconfigurable hash in place.  |
| 2026-04-18 23:31      | `0c55eec` | **1251**          | 0 (no .h)         | **Yes** (line 224)                | **Yes** (line 815)        | **Yes** (line 527)    | **S48 complete.** Full implementation of paper §APE Theorem 3.      |
| 2026-04-19 18:39-18:41| `9b04ca1` `49cfb98` `7d493a8` | **1260** | 0 (no .h)         | **Yes**                           | **Yes**                  | **Yes**              | **S49 complete.** Agent B wired sequencer_selfcheck. File last sighted with full impl. |
| **[gap of ~15 hours — regression event]** | — | — | — | — | — | — | **`trust_ape.c` replaced wholesale with 655-LOC pre-S48 version. Cause: unknown — no intermediate stash.** |
| 2026-04-20 09:48      | `1faee94` | **655**           | 0 (no .h)         | **No**                            | **No**                   | **No**               | First post-regression stash. File reverted. trust_ape.h still absent. |
| 2026-04-20 17:21      | `5013ad9` | 655               | 178               | No                                | No                       | No                   | **pre-S74 checkpoint committed to master.** `trust_ape.h` NEW — scaffolding declaring the now-absent symbols. |
| 2026-04-20 18:57      | `994136a` | 655               | 178               | No                                | No                       | No                   | S74 WIP stash (most recent).                                         |
| 2026-04-20 (current)  | HEAD      | 655               | 178               | No                                | No                       | No                   | Current state. Header advertises 94M; code has 3.                    |

### Key observations about the timeline

1. The first commit to master (`0408da8`, 2026-04-13) already has the **3-algo simplified version**. This is the pre-S48 baseline. When we say "regression" we mean the regression from the S48/S49 enriched version BACK to something functionally equivalent to this original baseline.
2. The squash checkpoint `5013ad9` (2026-04-20 17:21) collapsed **35 sessions** of working-tree history (S38-S73). The S48 rewrite and the S49 extensions existed only in this elided window. To a `git log` on master, neither event exists.
3. `trust_ape.h` was **created by the squash checkpoint** — meaning it was authored during the pre-S74 checkpoint-preparation process, AFTER the code had regressed. The header documents what `trust_ape.c` SHOULD have contained, as if transcribed from memory of Session 48's deliverable, without realizing the underlying code had been deleted.
4. The separation between "header describing 94M" and "code shipping 3" is the paper-vs-code bisimulation failure that Research D caught 14 sessions later.

### Why git log missed it

- No commit with the enriched code exists on master's linear history (`git log --first-parent master`).
- The enriched versions exist only as **stash merge commits** — 2-parent merges between `e2f4ed7` (master tip pre-checkpoint) and an unrelated commit representing working-tree state.
- `git log --all -S "apply_reconfigurable_hash"` only traverses **reachable** refs. Dangling stashes are unreachable after their checkpoint squashed around them.
- `git fsck --lost-found --full` enumerates unreachable objects — this is the entry point that Agent K missed.

---

## §3 String-Search Findings

### 3.1 On master's reachable history

```bash
git log --all -S 'apply_reconfigurable_hash' --oneline
# Only returns S74-era doc commits (d043482, f51a13d, 071b6aa, 5013ad9)
# where the string enters via trust_ape.h/ docs/, never via trust_ape.c
```

This is what led Agent K to conclude ASPIRATIONAL. It is correct for the reachable graph.

### 3.2 On dangling stashes (via `git show <dangling>:trust/kernel/trust_ape.c`)

`0c55eec` (2026-04-18 23:31 — end of S48):

```
line 20:   * ... through trust_ape_consume_proof_v2().
line 28:   * derive_hash_cfg() and apply_reconfigurable_hash() below.
line 144: static u8 ape_perm_table[APE_CFG_PERM_COUNT][8];
line 147: static void heap_permute_init(void)                       // Heap's algorithm enumeration
line 194: static inline void decode_cfg(const u8 *proof, struct ape_hash_cfg *out)
line 207:     out->perm_idx = (u16)((lo & 0xFFU) % APE_CFG_PERM_COUNT);
line 224: static void apply_reconfigurable_hash(const struct ape_hash_cfg *cfg, ...)
line 273:  * stage, applied AFTER apply_reconfigurable_hash().
line 322:    apply_reconfigurable_hash(&cfg, scratch, data_len);
line 527:    BUILD_BUG_ON(APE_CFG_TOTAL != 94371840ULL);
line 528:    BUILD_BUG_ON(APE_CFG_PERM_COUNT   != 720U);
line 561:            (unsigned long long)APE_CFG_TOTAL);
line 815: int trust_ape_consume_proof_v2(u32 subject_id, ...)
line 846:                      "trust_ape_consume_proof_v2 with real R_n\n",
line 1035: * NEW callers should use trust_ape_consume_proof_v2() and pass a real
line 1041:    return trust_ape_consume_proof_v2(subject_id, request, req_len, ...);
line 1094:     * trust_ape_consume_proof_v2() mutates state.nonce under entry->lock
```

`9b04ca1` (2026-04-19 18:39 — end of S49): same symbols, line offsets shift by ~9 (added S49 sequencer_selfcheck wrapper).

### 3.3 Function inventory in dangling `9b04ca1:trust_ape.c`

29 static helpers + public entry points:

| Lines  | Function                                         | Present in shipping 655-LOC? |
|--------|--------------------------------------------------|------------------------------|
| 61     | `DEFINE_PER_CPU(u64, ape_double_read_traps)`      | No                           |
| 76     | `DEFINE_PER_CPU(u64, ape_seq_advances)`           | No                           |
| 95     | `ape_pad_get` / `ape_pad_or` / `ape_pad_clear`    | No                           |
| 111    | `hash_algo_names[TRUST_HASH_CFG_COUNT]`           | Yes (3-algo)                 |
| 144    | `ape_perm_table[720][8]` — **720 perm table**     | **No**                       |
| 147    | `heap_permute_init` — **Heap's algorithm filler** | **No**                       |
| 194    | `decode_cfg` — **4-tuple extractor from P_n**     | **No**                       |
| 224    | `apply_reconfigurable_hash` — **perm+mask+rot**   | **No**                       |
| 275    | `cfg_to_underlying`                               | No                           |
| 285    | `derive_hash_cfg` (v2 — 4-tuple aware)             | Yes (downgraded to `% 3`)    |
| 301    | `compute_proof_v2`                                | No                           |
| 386-527| `ape_index_hash` / `_find` / `_insert` / `_remove`| **Yes** (S30 legacy, preserved) |
| 525    | `trust_ape_build_asserts` + 6 `BUILD_BUG_ON`s     | **No**                       |
| 543    | `trust_ape_init`                                  | Yes                          |
| 600    | `xchg_read_and_zero` — **atomic proof consumption** | **No**                      |
| 627    | `trust_ape_create_entity`                          | Yes                          |
| 763    | `trust_ape_destroy_entity`                         | Yes                          |
| 824    | **`trust_ape_consume_proof_v2`**                   | **No**                       |
| 1047   | `trust_ape_consume_proof` (v1 back-compat shim)    | Yes (but as full impl, not shim) |
| 1058   | `trust_ape_verify_chain`                           | Yes                          |
| 1089   | `trust_ape_get_nonce`                              | Yes                          |
| 1118   | `trust_ape_get_chain_length`                       | Yes                          |

**Total lines lost in regression: ~605 LOC of APE-specific code (720-perm table + heap_permute_init + decode_cfg + apply_reconfigurable_hash + cfg_to_underlying + compute_proof_v2 + build_asserts + xchg_read_and_zero + v2 consume path + all per-cpu counters + double-read trap).**

The shipping 655-LOC keeps the S30-era hash index (~180 LOC of FNV-1a open addressing — unrelated to reconfigurable hash) but is otherwise a scaffolded regression to the pre-S48 baseline.

---

## §4 Paper-vs-Code Mismatch Details

### 4.1 Paper section (Roberts/Eli/Leelee §APE Theorem 3)

> The reconfigurable hash `H_cfg(n)` has configuration space
>
> `cfg(n) = (perm, window, mask, rot)` where
> * `perm` ranges over 720 permutations (first 720 of 8! by Heap's algorithm)
> * `window` ∈ {0..255}
> * `mask` ∈ {0..15}
> * `rot` ∈ {0..31}
>
> producing `|Config| = 720 × 256 × 16 × 32 = 94,371,840` distinct configurations per step.
>
> **Theorem 3 (Reconfiguration Unpredictability):** `Pr[adversary predicts cfg(n+1)] ≤ 1/|Config| + negl(λ) = 1/94,371,840 + negl(λ) ≈ 2⁻²⁶·⁵ + negl(λ)`.

### 4.2 Shipping header (`trust/kernel/trust_ape.h:44-52`, authored at `5013ad9`)

```c
#define APE_CFG_PERM_COUNT     720U
#define APE_CFG_WINDOW_COUNT   256U
#define APE_CFG_MASK_COUNT      16U
#define APE_CFG_ROT_COUNT       32U

#define APE_CFG_TOTAL \
    ((u64)APE_CFG_PERM_COUNT * APE_CFG_WINDOW_COUNT * \
     APE_CFG_MASK_COUNT      * APE_CFG_ROT_COUNT)
```

The header promises paper-exact behavior.

### 4.3 Shipping implementation (`trust/kernel/trust_ape.c:41-55`, current HEAD)

```c
static const char *hash_algo_names[TRUST_HASH_CFG_COUNT] = {
    "sha256",       /* TRUST_HASH_CFG_SHA256 */
    "blake2b-256",  /* TRUST_HASH_CFG_BLAKE2B */
    "sha3-256",     /* TRUST_HASH_CFG_SHA3 */
};

static u32 derive_hash_cfg(const u8 *proof)
{
    u32 selector = proof[0] | (proof[1] << 8) |
                   (proof[2] << 16) | (proof[3] << 24);
    return selector % TRUST_HASH_CFG_COUNT;    /* % 3 */
}
```

The code ships `|Config| = 3`, `log₂(3) ≈ 1.58 bits` of adversarial uncertainty.

### 4.4 Security-quantity delta

- Paper Theorem 3 bound: `1/94,371,840 ≈ 2⁻²⁶·⁵` per-step
- Shipping Theorem 3 bound: `1/3 ≈ 2⁻¹·⁵⁸` per-step
- **Ratio:** the shipping system is **~31 million times weaker** at the step where Theorem 3 does its load-bearing work.

The outer SHA-256 step preserves non-replayability (Theorem 2) and proof-single-shot (Theorem 1). The loss is specifically on Theorem 3 — adversarial prediction of `cfg(n+1)`. A 3-element config space loses the underlying cryptographic hardness argument of the paper.

### 4.5 Compile-time guard that was supposed to prevent this

The S48 implementation included (`0c55eec:trust/kernel/trust_ape.c:525-541`):

```c
static inline void __maybe_unused trust_ape_build_asserts(void)
{
    BUILD_BUG_ON(APE_CFG_TOTAL != 94371840ULL);
    BUILD_BUG_ON(APE_CFG_PERM_COUNT   != 720U);
    BUILD_BUG_ON(APE_CFG_WINDOW_COUNT != 256U);
    BUILD_BUG_ON(APE_CFG_MASK_COUNT   != 16U);
    BUILD_BUG_ON(APE_CFG_ROT_COUNT    != 32U);
    BUILD_BUG_ON(APE_RESULT_HASH_LEN  != 32U);
    BUILD_BUG_ON((TRUST_PROOF_SIZE % 8) != 0);
}
```

with a prose comment: *"compile-fail if any session ever weakens the configuration space below the paper's claim."*

The guard worked as designed — it would compile-fail if anyone changed the macros. But the regression didn't weaken the macros in-place; it **removed the entire file contents** (replaced the whole `trust_ape.c` with an earlier version). A file-level rollback bypasses function-local `BUILD_BUG_ON`. The guard protected the wrong surface: it guarded the macros, but the threat was deletion of the guard itself.

This is worth keeping in mind for S75: bring-back must include the guard AND also a Kbuild-level or CI-level check for "if you remove the reconfigurable hash, the build fails" — e.g., a symbol-presence lint.

---

## §5 Session Memory Cross-Reference

### 5.1 Session 48 (2026-04-18) — paper conformance

`session48_10agent_paper_conformance.md:27`: "Agent 1: §SCP / §APE: reconfigurable hash **94,371,840 configs**, R_n action-result entanglement, atomic xchg read-and-zero, double-read trap — **trust_ape.c (rewrite) + trust_ape.h (new)**"

`session48_10agent_paper_conformance.md:59-60`:

| Paper concept                              | Implementation site                                  | Status |
|--------------------------------------------|------------------------------------------------------|--------|
| Self-Consuming Proof P_{n+1}=H_cfg(n)(...) | trust_ape.c reconfigurable hash + R_n entanglement   | ✓      |
| cfg(n) 94,371,840 configurations           | BUILD_BUG_ON(APE_CFG_TOTAL != 94371840ULL)          | ✓      |

`session48_10agent_paper_conformance.md:115`: "Migrate dispatcher call sites to pass real R_n to `trust_ape_consume_proof_v2()` (currently 5 sites pass NULL → 32-byte zero, with `pr_debug_once` warning). Agent 1 listed exact line numbers."

This memory is verified against dangling `0c55eec` — trust_ape.c:841-846 contains the `pr_debug_once("trust_ape: NULL result_hash in consume_proof ... migrate caller to trust_ape_consume_proof_v2 with real R_n\n")` string. The S48 author wrote the memory with the code in front of them.

### 5.2 Session 49 (2026-04-19) — named-role round

`session49_5agent_role_taxonomy.md:44`: "**Sequencer** (Agent B): `trust_ape.c:1025` — `(void)trust_invariants_advance_nonce()` on success path of `trust_ape_consume_proof_v2`, after entity nonce write-back, before return — error returns bypass it (preserves bind-to-success invariant)"

Cross-check: dangling `9b04ca1:trust_ape.c` at 1260 LOC. Line 1025 falls within the function spanning lines 824-1046 — the `trust_ape_consume_proof_v2` body. The cited patch is visible at `9b04ca1:trust_ape.c:1025` exactly as described.

### 5.3 Session 50 (2026-04-18 late) — production hardening

`session50_10agent_production_hardening.md:41`: "docs/roa-conformance.md overstates by ~40% (fictional A/B segment names, fictional ioctls, etc.) | I | **REWRITTEN.** 372 lines, every row cites real file:line. **Renamed 7 doc-fiction symbols to shipping names** (`A_AUTH_PROFILE`→`CHROMO_A_ACTION_HASH`, `cfg(n)`→`derive_hash_cfg`+`apply_reconfigurable_hash`, `TRUST_IOC_MEIOSIS_REQUEST/ACCEPT`→single `TRUST_IOC_MEIOSIS`, etc.)."

Note the critical phrase: *"Renamed 7 doc-fiction symbols to **shipping names**"*. S50 Agent I explicitly reconciled the doc to match code. The names `derive_hash_cfg` and `apply_reconfigurable_hash` were cited as shipping names. That reconciliation was honest at the time it happened. It became dishonest only after the S49→S50-era regression event deleted `apply_reconfigurable_hash` without updating `roa-conformance.md`.

### 5.4 Session 58 (2026-04-19) — Markov chains

`session58_10agent_markov_chains.md:22` (describing Agent A3's `trust_ape_markov.c`):

> "Statistical validator for APE reconfigurable hash output distribution. ... **Wiring deferred to S59:** needs `trust_ape_markov_validator()` call in `trust_ape_init()` after `trust_ape_sequencer_selfcheck()`."

The file `trust/kernel/trust_ape_markov.c` itself carries the prose comment (line 21):

> "*We CANNOT call apply_reconfigurable_hash() directly from this translation unit (it is `static` to trust_ape.c, which is locked to Agent 1 of S48). Using SHA-256 directly is a strict LOWER-BOUND on the chain's mixing...*"

This comment IS ONLY MEANINGFUL IF `apply_reconfigurable_hash()` EXISTS. Agent A3 wrote defensive prose about *not being able to call* a function they can *see is static in another TU*. If the function didn't exist, the comment would read "apply_reconfigurable_hash does not exist yet" — but it reads "apply_reconfigurable_hash IS static, LOCKED to Agent 1". This is direct evidence that at the time A3 wrote this (before the squash), the function was in the tree.

### 5.5 Session 74 (2026-04-20) — the detection event

`session74_research_architecture_build.md:86`: "**APE 94M→3 hash regression** — something during Phase 1 reduced reconfigurable hash space from 94M configs to 3. Triage-only by K; full fix deferred."

S74's own summary calls it a **regression**, not an aspirational gap. But the author attributes it to "Phase 1" (S74 itself), not to the prior session chain. The current investigation shows the regression happened BEFORE S74 started — at some point between S49 end (2026-04-19 18:40) and the pre-S74 checkpoint (2026-04-20 09:48).

### 5.6 Memory vs code consistency

Session memory is **consistent with the dangling-stash evidence**: S48 wrote the full implementation, S49 extended it, S50 reconciled docs, S58 wrote adjacent code assuming the function existed, and S74 detected the regression. The memory is not fabricated; the code IS gone; the question was just when and how.

**Answer to "when":** between dangling `9b04ca1` (2026-04-19 18:39) and dangling `1faee94` (2026-04-20 09:48) — a ~15-hour window with no intermediate stash captured. Most likely mechanism: a `git checkout` of an older `trust_ape.c` to fix an unrelated build break, or a stash-pop that discarded working-tree changes. No git commit references the event because no commit ever landed the S48 work to master.

---

## §6 Verdict with Evidence

### 6.1 Classification

**REGRESSION — with an unusual trail.**

The S48/S49 implementation:
- Compiled clean against kernel 6.18 (per S48 memory)
- Passed its own BUILD_BUG_ON assertions
- Was exercised by a 10-agent dispatch + Agent B's Theorem 2 wiring
- Was referenced by S50 doc rewrite (roa-conformance.md)
- Was referenced by S58 adjacent code (trust_ape_markov.c)

It was real code. It shipped into a working tree. Then it disappeared without a committing trail. This is **regression via working-tree manipulation**, not regression via commit+revert.

Why this matters for classification:
- A **commit+revert** regression is easy to find: `git log -p` shows both sides. Agent K's method would have found it.
- A **working-tree loss** regression is invisible to `git log` unless caught by `git fsck --lost-found`. This is what happened.
- An **aspirational** header with no code ever would have NO dangling stash containing the implementation. Here we have **four such dangling stashes** (`7fa89b8`, `0c55eec`, `9b04ca1`, `49cfb98`, `7d493a8`) — the implementation was present on disk for ~26 hours across at least 5 distinct working-tree snapshots.

### 6.2 Highest-confidence evidence (ranked)

1. **`git show 0c55eec:trust/kernel/trust_ape.c` is 1251 lines of working C code** containing `apply_reconfigurable_hash`, the 720-perm table, `compute_proof_v2`, `xchg_read_and_zero`, and `BUILD_BUG_ON(APE_CFG_TOTAL != 94371840ULL)`. This is a direct refutation of "the code never existed". The code exists, right now, in our own git object store.
2. **`git show 9b04ca1:trust/kernel/trust_ape.c:1025`** is the exact `(void)trust_invariants_advance_nonce()` statement cited by the S49 memory.
3. **`trust_ape_markov.c:21` prose comment** referring to `apply_reconfigurable_hash` as a `static` symbol in another TU — the adjacent-code author could see it at the time of writing.
4. **Paper-vs-implementation mismatch quantified:** header says 94,371,840, code says 3 — a 7-order-of-magnitude gap that does not arise from good-faith aspirational scaffolding (which would match in structure, just not in performance).

### 6.3 Counter-arguments considered

**"Maybe the header was written AFTER code regression, trying to document what the paper said but code never followed."** — Refuted by the dangling-stash evidence. The CODE was richer than the current header, in the wider window before the .h file was even created. The .h file was authored DURING the squash-checkpoint as a post-hoc transcription of what memory said the code should contain.

**"Maybe the session memory is wrong / hallucinated."** — Refuted by the direct `git show` retrievability of the cited code. The memory quotes line numbers that exist in the dangling stashes.

**"Maybe Agent K's `git log --all -S` check is authoritative."** — Refuted: `-S` on master's reachable history genuinely misses unreachable objects. Agent K's methodology was sound for their scope, but their scope was incomplete. `git fsck --lost-found` is required for completeness.

**"Maybe the dangling stashes are from a different project / different branch."** — Refuted: `git show 0c55eec --stat` enumerates dozens of files that match this project's exact layout (ai-control/, trust/kernel/, services/scm, etc.). These are ARCHWINDOWS stashes.

---

## §7 Recommended S75 Action

### 7.1 Primary recommendation: BRING-BACK from dangling stash

**Estimated LOC:** ~605 LOC restore (1260 LOC → current 655 LOC delta) + ~20-40 LOC of glue for post-regression context (S58 markov validator wire, S63+ contusion_dictionary interactions, .h reconciliation).

**Procedure:**

1. **Recover the enriched file:**
   ```bash
   git show 9b04ca1:trust/kernel/trust_ape.c > /tmp/trust_ape_s49.c
   ```
   This gives us the S49-end version at 1260 LOC with every function we need.

2. **Three-way merge:** diff the recovered file against the current 655-LOC shipping version to identify the ~180-LOC of S30/S38-S73 changes that should be preserved in the new version (FNV-1a hash index, other unrelated fixes that happened on top of the 655-LOC base).

3. **Port the recovered functions** onto the current shipping base:
   - `ape_perm_table[720][8]`
   - `heap_permute_init()`
   - `decode_cfg()`
   - `apply_reconfigurable_hash()`
   - `cfg_to_underlying()`
   - `compute_proof_v2()`
   - `trust_ape_build_asserts()` with all 6 BUILD_BUG_ONs
   - `xchg_read_and_zero()`
   - `trust_ape_consume_proof_v2()` — the full 220-LOC v2 entry point
   - Per-CPU counters for double-read traps and sequencer advances

4. **Reconcile with `trust_ape_markov.c`:** the markov validator's `CANNOT call apply_reconfigurable_hash() directly` comment becomes accurate again. Consider replacing SHA-256-only validation with a composite validation that does call the reconfigurable hash through a test-only export.

5. **Reconcile `trust_ape.h`:** declarations now match implementations. `trust_ape_consume_proof_v2` has a body. Remove or mark as FUTURE any sub-symbols still missing.

6. **Reconcile 5 dispatcher call sites:** per S48 memory handoff, trust_dispatch.c/trust_core.c/trust_fused.c have legacy v1 callers. Per S50 memory these WERE migrated (§41 of S50 lists the migration). If they need re-migration, the S50 pattern is documented.

7. **CI lint:** add a grep-based lint in `scripts/build-packages.sh` or a separate `scripts/verify_ape_conformance.sh` that fails if:
   - `trust_ape.c` lacks `apply_reconfigurable_hash`
   - `trust_ape.c` lacks `94371840ULL`
   - `trust_ape.c` lacks `720U`
   This prevents a future working-tree loss from happening silently.

### 7.2 Alternative: doc-only fix (downgrade paper + header)

Agent K's path (a). Estimated **~40-60 LOC** across:
- `trust_ape.h` — rewrite comment, remove APE_CFG_* macros
- `docs/roa-conformance.md` — cite real symbols (`derive_hash_cfg`, `compute_proof`) instead of fictional ones
- `tests/integration/test_roa_conformance.py:145` — assert against real symbols
- `docs/paper-vs-implementation.md` — document reduced Theorem 3 bound
- Paper erratum (Zenodo 18710335) — note shipping implementation is `1/3` not `1/94M`

**Why the bring-back is preferable:**
- We already wrote the 94M-config code. It is retrievable with one `git show`.
- The paper erratum is a legitimate author cost — a paper that says "94M" and ships "3" destroys credibility. Downgrading the paper costs credibility we already earned with the S48 work.
- The bring-back closes the bisimulation gap permanently and the CI lint ensures it stays closed.
- Net cost of bring-back vs doc-fix: ~560 net LOC, ~1-2 sessions of validation (chi-square re-run, adversarial harness coverage).

### 7.3 Secondary — prevent future working-tree loss

Even if the primary recommendation is accepted, add:
- **Pre-commit hook:** verify that `trust_ape.c` has not shrunk by >50% since last commit.
- **CI workflow:** on PR, run `grep -c apply_reconfigurable_hash trust/kernel/trust_ape.c` and fail if count is 0.
- **Memory-backed invariant:** session memory should state "trust_ape.c contains the 94M reconfigurable hash" as a long-term project invariant, checked at each session start.

---

## §8 Appendix — Investigation Methodology Notes

What worked:
- `git fsck --lost-found --full` enumerated 7 dangling commits + dozens of dangling blobs.
- `git show <dangling>:<path>` retrieved arbitrary file versions from unreachable objects.
- `git show <dangling> --stat | grep trust_ape` quickly identified which dangling commits touched the file.
- Session memory cross-reference was the Rosetta Stone that told us the missing code existed and what it should look like.
- `git blame | awk '{print $1}' | sort -u | wc -l` gave the "is this file trivially authored" signal — 1 unique author-commit for trust_ape.h told us it was a single-shot scaffolding insert, not iterative development.

What didn't work (false negatives):
- `git log --all -S 'symbol'` missed because dangling commits are unreachable.
- `git log --diff-filter=D` missed because the deletion happened in working-tree, not in a commit.
- `git log --all --oneline -- <file>` missed because the 35-session squash hid intermediate history.

Key lesson: **when session memory claims contradict `git log`, search the object store.** `git log` reflects the reachable history; memory may reflect the working-tree history that never made it into a reachable commit. Dangling stash commits are the bridge.

---

**End of archaeology.**
