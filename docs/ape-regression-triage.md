# APE Reconfigurable-Hash Regression Triage

**Investigation only — no code changes in this session.**

Dispatched as part of the S74 Agent K integration brief (Finding #10).
Scope: determine whether `apply_reconfigurable_hash()` and
`trust_ape_consume_proof_v2()` were ever implemented in the shipping
`trust/kernel/trust_ape.c`, or whether the header / conformance-doc
claims are aspirational.

---

## 1. Symbols and what the docs claim

`trust/kernel/trust_ape.h:88` declares
`trust_ape_consume_proof_v2(subject_id, request, req_len,
action_result_hash, hashlen, proof_out)` — the extended v2 proof-step
entry point.

`trust/kernel/trust_ape.h:44-52` declares four compile-time macros:

```c
#define APE_CFG_PERM_COUNT     720U
#define APE_CFG_WINDOW_COUNT   256U
#define APE_CFG_MASK_COUNT      16U
#define APE_CFG_ROT_COUNT       32U
#define APE_CFG_TOTAL (720 * 256 * 16 * 32)  /* 94,371,840 */
```

with a comment claiming `BUILD_BUG_ON` asserts `APE_CFG_TOTAL` in
`trust_ape.c`.

`docs/roa-conformance.md:58-60` cites both symbols as `VERIFIED`:

| Row                              | Cited location                              | Status           |
|----------------------------------|---------------------------------------------|------------------|
| Proof consumption                | `trust_ape_consume_proof_v2()` @ `trust_ape.c:815` | VERIFIED (claimed) |
| Reconfigurable hash kernel       | `apply_reconfigurable_hash()` @ `trust_ape.c:224` | VERIFIED (claimed) |

`docs/architecture-v2.md:465` flags this as an URGENT regression.

`docs/research/s74_d_crypto_audit.md:148, 540, 666` flags the same.

`tests/integration/test_roa_conformance.py:145` has
`assert "apply_reconfigurable_hash" in src` — which would fail if the
test is actually run.

---

## 2. Shipping reality

`trust/kernel/trust_ape.c` is **655 lines** (verified with `wc -l` at
commit 071b6aa). No function `apply_reconfigurable_hash` or
`trust_ape_consume_proof_v2` exists. Functions defined in the file:

| Line | Signature                                         |
|------|---------------------------------------------------|
| 52   | `static u32 derive_hash_cfg(const u8 *proof)`     |
| 65   | `static int compute_proof(u32 hash_cfg, ...)`     |
| 247  | `void trust_ape_init(void)`                        |
| 275  | `int trust_ape_create_entity(...)`                 |
| 404  | `int trust_ape_destroy_entity(u32 subject_id)`     |
| 454  | `int trust_ape_consume_proof(u32, const u8*, u32, ...)` |
| 574  | `int trust_ape_verify_chain(u32 subject_id)`       |
| 605  | `int trust_ape_get_nonce(...)`                     |
| 634  | `int trust_ape_get_chain_length(...)`              |

`TRUST_HASH_CFG_COUNT = 3` at `trust/include/trust_types.h:276`, and
`hash_algo_names[]` at `trust_ape.c:41` lists exactly three:

- SHA-256
- BLAKE2b-256
- SHA3-256

No 720-perm table, no 256-window selector, no 16-mask selector, no
32-rot selector. `derive_hash_cfg()` at :52 computes
`selector % TRUST_HASH_CFG_COUNT` (so `% 3`), which is directly
incompatible with the header's claimed 94,371,840 configurations.

---

## 3. Git archaeology

Searched the full repo history:

```
git log --all -p -S "apply_reconfigurable_hash" -- trust/kernel/trust_ape.c
```

**Result: zero hits.** `apply_reconfigurable_hash` has never been part
of `trust_ape.c` in any recorded commit.

Same search for `consume_proof_v2` in `trust_ape.c`: **zero hits.**

The symbols DO appear in the repo, but only in:

- `trust/kernel/trust_ape.h` (declaration only — no implementation
  side ever existed)
- `docs/roa-conformance.md` (row claims VERIFIED — the claim is false)
- `docs/architecture-v2.md`, `docs/agent10_integration_brief.md`,
  `docs/research/s74_d_crypto_audit.md` (all of which flag this as a
  regression)
- `tests/integration/test_roa_conformance.py:145` (assert that would
  fail if the test is run against a real tree)

Commit 5013ad9 (the pre-S74 checkpoint) is the genesis of `trust_ape.c`
in this repo. Prior S30-S37 history is elided (squashed into the
checkpoint). So the 1038-line "older version" that `s74_d` references
is either (a) lost to the pre-checkpoint history or (b) never existed
and the cited line numbers are scaffolded documentation written before
the code caught up.

No prior branch in `git branch -a` contains a richer `trust_ape.c`.

---

## 4. Cross-reference with the paper

Zenodo record 18710335 §APE (Authority Proof Engine) — the paper as
written describes the self-consuming proof formula:

```
P_{n+1} = H_{cfg(n)}(P_n || R_n || SEED || N_n || T_n || S_n)
```

where `cfg(n)` is extracted from the consumed P_n and selects:

- one of 720 permutations (first 720 of 8! by Heap's algorithm)
- one of 256 hash-window sizes
- one of 16 mask patterns
- one of 32 pre-rotations

producing 720·256·16·32 = 94,371,840 total configurations.

The shipping code's 3-algo `derive_hash_cfg(...) % 3` is a
**drastically simpler** form of the paper's `cfg(n)`. Both satisfy the
"proof consumes itself and influences the next hash" architectural
guarantee — the reconfigurability is present — but the cardinality of
the config space is 7 orders of magnitude lower than the paper claims.

From a security standpoint: 94M configs provides `log2(94M) ≈ 26.5`
bits of per-step adversarial uncertainty; 3 configs provides
`log2(3) ≈ 1.58` bits. The composite chain still admits
`P_n -> P_{n+1} -> ...` non-replayability by the outer SHA-256 step,
so the "proofs are single-shot" property is preserved. The
"adversarial prediction of cfg(n+1) is infeasible" property from the
paper's Theorem 3 is NOT materially upheld by a 3-element config space
— an adversary guesses `1/3` vs `1/94M`.

---

## 5. Classification

**Status: ASPIRATIONAL, never implemented in any git-tracked commit.**

This is NOT a regression in the software-engineering sense — no commit
removed these functions; they were never there. The
`trust_ape.h:44-52` macros and the `consume_proof_v2` declaration are
forward-declared scaffolding the paper/spec author intended to back
with code. The code has never caught up with the header.

The S74 research reports (`s74_d`, `architecture-v2`) correctly flag
this as a conformance gap. The docs/roa-conformance.md row marking
`apply_reconfigurable_hash` as VERIFIED is factually incorrect;
whoever last edited that doc did not check the cited line.

---

## 6. Recommendations (for S75 user decision — NOT this session)

Three paths forward, ranked by risk:

### (a) Amend docs + header to reflect 3-algo shipping reality (~40 LOC)

- Delete the 720/256/16/32 macros from `trust_ape.h:44-52`.
- Replace the formula comment at :1-35 with the actual 3-algo form.
- Mark `trust_ape_consume_proof_v2` declaration as FUTURE / remove.
- Fix `docs/roa-conformance.md:58` to cite `compute_proof` and
  `derive_hash_cfg` (which exist) instead of the two fictional
  symbols.
- Update `tests/integration/test_roa_conformance.py:145` to assert
  against real symbols.
- Paper itself (Zenodo 18710335) would need erratum noting the shipping
  implementation uses a reduced 3-algo `H_cfg` whose Theorem 3 bound
  is `1/3 + negl(lambda)` rather than `1/94M + negl(lambda)`.

**Risk:** lowest. Closes the documentation regression immediately.
**Cost:** erratum on the paper is author-owned, not engineering-owned.

### (b) Implement the 94M-config reconfigurable hash (~300-400 LOC)

- Add `apply_reconfigurable_hash()` at `trust_ape.c` that takes
  `cfg(n)` (4-tuple extracted from bytes [0:25] of P_n) and a digest
  input, applies perm + window + mask + rot, then hashes.
- Replace `derive_hash_cfg()` at :52 with a struct-return version
  that unpacks the 4-tuple.
- Table of 720 permutations (5760 bytes) enumerated from first 720 of
  Heap's 8! = 40,320.
- `trust_ape_consume_proof_v2` wiring: accept `action_result_hash`,
  include in the `P_n || R_n || ...` input.
- `BUILD_BUG_ON(APE_CFG_TOTAL != 94371840)` as the header claims.
- Adversarial statistical test — re-verify `trust_ape_markov.c`
  against the composite chain, not just SHA-256 alone.

**Risk:** highest. Touches the APE fast path; requires chi-square
validation; adversarial test surface grows.
**Cost:** ~300-400 LOC + 1-2 sessions of validation.

### (c) Investigate-only: keep triage open, defer decision

- This file becomes the canonical triage artifact.
- S75 user reviews + decides between (a) and (b).
- No immediate action in S74. Current build works; APE passes the
  adversarial tests defined by `trust_ape_markov.c` at its current
  threshold.

**Recommendation: (a) for velocity, (b) for paper conformance.**
User should pick based on whether paper erratum is cheaper than
300-400 LOC of crypto engineering + re-validation.

---

## 7. Agent-K commitment this session

Per the Agent K brief: "Do NOT attempt bring-back this session — S75
decision." This triage file is the deliverable. No code in
`trust_ape.c`, `trust_ape.h`, `docs/roa-conformance.md`, or the
conformance test changes in this session.

---

## 8. Sysfs-path triage note (Finding #9 addendum)

Kept in this file per the brief ("use it as a general 'triage notes'
file"). Agent K fixed `trust_quorum.c:194` to register its counters
under the shared `/sys/kernel/trust/` parent (now exposed via
`trust_stats_parent_kobj()`). `trust_algedonic.c:267` and
`trust_morphogen.c` (per-attr registration) remain on their separate
roots (`/sys/kernel/algedonic/*`, `/sys/kernel/morphogen/*`) for S75.

Unifying all three under `/sys/kernel/trust/` is a clean 3-file patch
(each creates its kobject via `trust_stats_parent_kobj()` with
fallback to `kernel_kobj`) but the morphogen file already has a
non-trivial sysfs surface and changing the path breaks whoever is
tailing it. Defer to S75 with explicit documentation migration.

Documented paths after S74 Agent K:

- `/sys/kernel/trust/stats`       — trust_stats (unchanged)
- `/sys/kernel/trust/caps`        — trust_stats (unchanged)
- `/sys/kernel/trust/quorum/*`    — trust_quorum (FIXED in S74)
- `/sys/kernel/trust_invariants/*` — trust_invariants (unchanged, S75)
- `/sys/kernel/algedonic/*`       — trust_algedonic (S74 new; S75 may unify)
- `/sys/kernel/morphogen/*`       — trust_morphogen (S74 new; S75 may unify)

---

**End of triage.**
