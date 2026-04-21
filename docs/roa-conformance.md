# Root of Authority (RoA) — Paper-to-Implementation Conformance

**Paper:** *Root of Authority* — Roberts / Eli / Leelee
**Zenodo record:** 18710335
**DOI:** [10.5281/zenodo.18710335](https://doi.org/10.5281/zenodo.18710335)

This document maps every named concept from the RoA paper to its concrete location
in this repository. It is the canonical conformance reference and the basis for
`scripts/diag-roa.sh` and `tests/integration/test_roa_conformance.py`.

Every row marked **VERIFIED** has a `file:line` citation to a symbol that
currently exists in the tree. If you add a paper-cited concept, add a row.
If you delete one, delete the row. The "Deviations from paper" section at
the bottom enumerates every place the project name diverges from the
paper's terminology — those rows MUST stay accurate or the doc lies.

Session 50 / Agent I rewrote this file end-to-end. Pre-S50 versions
referenced symbols (`A_AUTH_PROFILE`, `cfg(n)`, `trust_state_get_C/S/P/G/L`,
`trust_assign_sex`, `TRUST_IOC_MEIOSIS_REQUEST/ACCEPT`) that never existed
in shipping code; those rows have been replaced with their real-symbol
equivalents OR moved into Deviations.

---

## 1. Authority State `A_t = (C_t, S_t, P_t, G_t, L_t)`

The five-tuple authority state is materialised in the kernel `trust_subject_t`
struct (496 bytes) and exposed to userspace via the read-only macros declared
in `trust_types.h`.

| Symbol | Meaning                                | Real accessor / field                      | Citation                                                | Status   |
|--------|----------------------------------------|--------------------------------------------|---------------------------------------------------------|----------|
| `C_t`  | Token balance (signed; can go negative)| `authority_C(s)` -> `s->tokens.balance`    | `trust/include/trust_types.h:596`                       | VERIFIED |
| `S_t`  | Trust score in [-1000, +1000]          | `authority_S(s)` -> `s->trust_score`       | `trust/include/trust_types.h:597`                       | VERIFIED |
| `P_t`  | Current proof register (32 B digest)   | `authority_P(s)` -> `s->proof.proof[]`     | `trust/include/trust_types.h:602`                       | VERIFIED |
| `G_t`  | 16-bit generation, packed in TRC bytes | `authority_G(s)` -> `_g_t_hi:_g_t_lo`      | `trust/include/trust_types.h:605`                       | VERIFIED |
| `L_t`  | Sex axis TRUST_SEX_XX / TRUST_SEX_XY   | `authority_L(s)` (+ `authority_L_valid()`) | `trust/include/trust_types.h:612`                       | VERIFIED |

The wire form returned by the read ioctl is `trust_authority_state_t`
(24 bytes, packed) at `trust/include/trust_types.h:618`. The ioctl itself
is `TRUST_IOC_AUTHORITY_STATE` (NR=133, dir RW) at
`trust/include/trust_ioctl.h:454`.

---

## 2. Self-Consuming Proof (Authority Proof Engine)

Section 4.2 of the paper defines proofs as one-shot artefacts that
authenticate once and then are destroyed. The reconfigurable hash
function whose configuration is derived from the consumed proof
permutes under generation index, so a captured proof cannot be replayed
across epochs.

| Concern                          | Real symbol / location                                                            | Status   |
|----------------------------------|------------------------------------------------------------------------------------|----------|
| Proof consumption (consume = destroy) | `trust_ape_consume_proof_v2()` at `trust/kernel/trust_ape.c:825`              | IMPLEMENTED (S48 + S74 recovery, faf6d8e) |
| Legacy 1-arg shim (forwards to v2 with NULL R_n) | `trust_ape_consume_proof()` at `trust/kernel/trust_ape.c:1067`         | IMPLEMENTED |
| Reconfigurable hash kernel       | `apply_reconfigurable_hash()` at `trust/kernel/trust_ape.c:225`                    | IMPLEMENTED (S48 + S74 recovery, faf6d8e) |
| 720-entry permutation table      | `ape_perm_table[APE_CFG_PERM_COUNT][8]` at `trust/kernel/trust_ape.c:145`          | IMPLEMENTED |
| Permutation table initialisation | `heap_permute_init()` (Heap's algorithm) at `trust/kernel/trust_ape.c:148`         | IMPLEMENTED |
| cfg(n) decode (perm/window/mask/rot) | `decode_cfg()` at `trust/kernel/trust_ape.c:195`                               | IMPLEMENTED |
| cfg-aware SHA kernel             | `compute_proof_v2()` at `trust/kernel/trust_ape.c:302`                             | IMPLEMENTED |
| Hash-config derivation (legacy selector) | `derive_hash_cfg()` at `trust/kernel/trust_ape.c:286`                      | IMPLEMENTED |
| `APE_CFG_TOTAL == 94371840` build-time assert | `BUILD_BUG_ON` inside `trust_ape_build_asserts()` at `trust/kernel/trust_ape.c:528` | IMPLEMENTED |
| Atomic read-and-zero of P_n      | `xchg_read_and_zero()` at `trust/kernel/trust_ape.c:601`                           | IMPLEMENTED |
| Proof-state struct               | `trust_proof_state_t` at `trust/include/trust_types.h:339`                         | VERIFIED |
| `seed[32]` write-once            | `trust_proof_state_t.seed` + `seed_set` flag (same struct)                         | VERIFIED |

### 2.1 What `apply_reconfigurable_hash()` actually does

Per the block comment at `trust/kernel/trust_ape.c:214-224`, the
transform is a constant-time three-stage in-place rewrite applied to
the proof input buffer **before** the final SHA-2 / SHA-3 / BLAKE2b
stage:

1. **Per-byte left-rotate** by `cfg->rot & 0x07` bits (rot ∈ {0..31},
   folded mod 8 — the upper 2 bits were reserved for future
   large-byte-width substrates and are currently redundant but kept in
   `APE_CFG_ROT_COUNT = 32` to preserve the paper's 5-bit rot field).
2. **Window XOR-mask** over `cfg->window`-sized chunks (window ∈
   {1..256}). The 16-byte mask pattern is derived from the 4-bit
   `cfg->mask` field.
3. **8-byte block permutation** driven by `ape_perm_table[cfg->perm_idx]`
   (perm_idx ∈ {0..719}). The 720 permutations are the first 720
   enumerated by Heap's algorithm (`heap_permute_init()` at
   `trust/kernel/trust_ape.c:148`, populating the 5760-byte
   `ape_perm_table` declared at `trust/kernel/trust_ape.c:145`).

Post-transform, `compute_proof_v2()` dispatches to one of three
underlying SHA primitives (`sha256`, `blake2b-256`, `sha3-256` —
`hash_algo_names[]` at `trust/kernel/trust_ape.c:112`) selected by
`cfg_to_underlying()` at `trust/kernel/trust_ape.c:276` (perm_idx mod
`TRUST_HASH_CFG_COUNT`). The `_v2` proof variant is therefore
cfg-aware per paper §SCP eq. (1), with the `R_n` result-entanglement
term threaded through at `trust_ape.c:975`.

Note: the paper's symbolic name for the reconfigurable hash is `H_cfg(n)`.
The shipping code splits it across `derive_hash_cfg()` (which builds a
`struct ape_hash_cfg` from the consumed proof) and
`apply_reconfigurable_hash()` (which executes the permutation). See
Deviations §A below.

### 2.2 Configuration-space richness

The four fields compose to `720 × 256 × 16 × 32 = 94,371,840`
configurations (`APE_CFG_TOTAL` at `trust/kernel/trust_ape.h:50-52`),
compile-asserted by `BUILD_BUG_ON(APE_CFG_TOTAL != 94371840ULL)` inside
`trust_ape_build_asserts()` at `trust/kernel/trust_ape.c:528`.

**Genuine novelty caveat.** The 94M count is a *richness* property, not
the primary APE novelty. The primary novelty — per research-D §3.1 and
`docs/paper-vs-implementation.md` §2.T-ape-novelty — is the **`S_n`
behavioral-state binding** (chromosome checksum folded into the proof
input), which entangles cryptographic chain integrity with
application-semantic subject state. A forged / replayed proof whose
`S_n` does not match the current chromosomal fingerprint cannot pass
verification, regardless of how well the attacker modeled `P_n` or
`cfg(n)`. The reconfigurable-hash richness hardens against cfg-prediction
attacks; the behavioral-state binding is what makes this primitive
unlike prior hash-chain literature (Lamport 1981, PayWord 1996, sponge
constructions — see `docs/paper-vs-implementation.md` §2.T-ape-lamport).

---

## 3. Chromosomes — 23 A-segments + 23 B-segments

Per Section 5.3, every subject carries 23 paired chromosomal segments.
A-segments are runtime-mutable behavioural genes; B-segments are static
identity genes. The 23rd pair encodes the sex-determination axis.

Implementation: `trust/kernel/trust_chromosome.c` + struct
`trust_chromosome_t` at `trust/include/trust_types.h:290`. All segment
indices are spelled `CHROMO_A_*` / `CHROMO_B_*` in code (NOT
`A_AUTH_PROFILE` etc. as the paper uses — see Deviations §B).

### A-segments (runtime / behavioural) — `trust/include/trust_types.h:197-219`

| #  | Real symbol                | Role (paraphrased)                                         |
|----|----------------------------|-----------------------------------------------------------|
| 0  | `CHROMO_A_ACTION_HASH`     | Rolling hash of recent action sequence                    |
| 1  | `CHROMO_A_TOKEN_BALANCE`   | Current metabolic token state                             |
| 2  | `CHROMO_A_TRUST_STATE`     | Trust-score trajectory fingerprint                        |
| 3  | `CHROMO_A_THERMAL`         | CPU/resource usage intensity                              |
| 4  | `CHROMO_A_MEMORY`          | Memory allocation pattern hash                            |
| 5  | `CHROMO_A_SYSCALL_CACHE`   | Syscall frequency distribution hash                       |
| 6  | `CHROMO_A_EXEC_PATH`       | Code execution path hash                                  |
| 7  | `CHROMO_A_NET_PATTERN`     | Network behaviour pattern hash                            |
| 8  | `CHROMO_A_FILE_PATTERN`    | File access pattern hash                                  |
| 9  | `CHROMO_A_IPC_PATTERN`     | IPC/signal pattern hash                                   |
| 10 | `CHROMO_A_TIMING`          | Timing/jitter profile                                     |
| 11 | `CHROMO_A_ERROR_RATE`      | Error/failure rate fingerprint                            |
| 12 | `CHROMO_A_ESCALATION`      | Escalation request pattern hash                           |
| 13 | `CHROMO_A_SPAWN_RATE`      | Process spawning rate fingerprint                         |
| 14 | `CHROMO_A_IO_PATTERN`      | I/O access pattern hash                                   |
| 15 | `CHROMO_A_CAPABILITY_USE`  | Capability usage distribution hash                        |
| 16 | `CHROMO_A_DOMAIN_CROSS`    | Cross-domain transfer frequency hash                      |
| 17 | `CHROMO_A_AUDIT_TRAIL`     | Audit-trail signature hash                                |
| 18 | `CHROMO_A_DEPENDENCY`      | Dependency-graph position hash                            |
| 19 | `CHROMO_A_LIFETIME`        | Process lifetime behaviour hash                           |
| 20 | `CHROMO_A_ENTROPY`         | Behavioural entropy measurement                           |
| 21 | `CHROMO_A_CONFORMANCE`     | Rolling conformance score                                 |
| 22 | `CHROMO_A_SEX`             | 23rd pair: behavioural conformance (XY determination)     |

Status: VERIFIED — all 23 macros grep-anchored in
`trust/include/trust_types.h:197-219`.

### B-segments (static / identity) — `trust/include/trust_types.h:222-244`

| #  | Real symbol                | Role (paraphrased)                                         |
|----|----------------------------|-----------------------------------------------------------|
| 0  | `CHROMO_B_BINARY_HASH`     | Executable binary hash                                    |
| 1  | `CHROMO_B_LIBRARY_DEPS`    | Library dependency-chain hash                             |
| 2  | `CHROMO_B_CONFIG_HASH`     | Configuration / registry hash                             |
| 3  | `CHROMO_B_INSTALL_SRC`     | Package / install-source fingerprint                      |
| 4  | `CHROMO_B_SIGNATURE`       | Code-signature verification hash                          |
| 5  | `CHROMO_B_PERMISSIONS`     | File-permission state hash                                |
| 6  | `CHROMO_B_OWNER`           | Owner uid/gid fingerprint                                 |
| 7  | `CHROMO_B_SECTION_HASH`    | PE/ELF section layout hash                                |
| 8  | `CHROMO_B_IMPORT_TABLE`    | Import-address-table hash                                 |
| 9  | `CHROMO_B_EXPORT_TABLE`    | Export-table hash                                         |
| 10 | `CHROMO_B_RESOURCE_HASH`   | Embedded-resource hash                                    |
| 11 | `CHROMO_B_MANIFEST`        | Application-manifest hash                                 |
| 12 | `CHROMO_B_CERT_CHAIN`      | Certificate-chain fingerprint                             |
| 13 | `CHROMO_B_RELOCATION`      | Relocation-table hash                                     |
| 14 | `CHROMO_B_DEBUG_INFO`      | Debug / symbol-info hash                                  |
| 15 | `CHROMO_B_COMPILER_ID`     | Compiler / toolchain fingerprint                          |
| 16 | `CHROMO_B_ABI_COMPAT`      | ABI compatibility hash                                    |
| 17 | `CHROMO_B_FUSE_STATE`      | Hardware fuse / efuse state                               |
| 18 | `CHROMO_B_BOOT_CHAIN`      | Boot-chain verification hash                              |
| 19 | `CHROMO_B_TPM_STATE`       | TPM / measured-boot state hash                            |
| 20 | `CHROMO_B_HW_IDENTITY`     | Hardware-identity fingerprint                             |
| 21 | `CHROMO_B_FIRMWARE`        | Firmware version / hash                                   |
| 22 | `CHROMO_B_SEX`             | 23rd pair: construction conformance (XY determination)    |

Status: VERIFIED — all 23 macros grep-anchored in
`trust/include/trust_types.h:222-244`.

---

## 4. Sex Determination XX / XY and conformance threshold

Section 6.1: subjects are typed XX or XY at birth from a confidence
function over their behavioural and constructional conformance scores.

| Concern                       | Real symbol / location                                                  | Status   |
|-------------------------------|-------------------------------------------------------------------------|----------|
| Threshold getter (per-mille)  | `trust_sex_threshold_get()` at `trust/kernel/trust_core.c:83`           | VERIFIED |
| Threshold setter              | `trust_sex_threshold_set()` at `trust/kernel/trust_core.c:92`           | VERIFIED |
| Threshold sysfs node          | `/sys/kernel/trust/sex_threshold` (RW u32, default 700/1000)            | VERIFIED |
| 4-state quadrant taxonomy     | `CHROMO_SEX_XX/XY/YX/YY` at `trust/include/trust_types.h:250-253`       | VERIFIED |
| 2-state paper axis            | `TRUST_SEX_XX / TRUST_SEX_XY` at `trust/include/trust_types.h:273-274`  | VERIFIED |
| Mirrored on subject struct    | `trust_subject_t.sex` + `sex_valid` at `trust/include/trust_types.h:570`| VERIFIED |
| L_t pack byte (authoritative) | `trust_trc_t._l_t_pack` at `trust/include/trust_types.h:519`            | VERIFIED |

Note: there is no symbol named `trust_assign_sex` or `trust_conf_eval` in
the tree (the pre-S50 doc claimed both). The conformance computation
lives inline in `trust_chromosome.c` and is folded into the 4-state -> 2-state
collapse documented in `trust_types.h:255-272`. See Deviations §C.

---

## 5. Mitosis

Section 6.3: a parent subject replicates by copying B-segments and
randomising a configurable subset of A-segments.

| Concern                       | Real symbol / location                                                  | Status   |
|-------------------------------|-------------------------------------------------------------------------|----------|
| Paper-spec entry point        | `trust_mitosis()` at `trust/kernel/trust_lifecycle.c:1639`              | VERIFIED |
| fork/clone-hookable form      | `trust_mitosis_by_id()` at `trust/kernel/trust_lifecycle.c:1551`        | VERIFIED |
| Legacy mitotic-divide path    | `trust_lifecycle_mitotic_divide()` at `trust/kernel/trust_lifecycle.c:307` | VERIFIED |
| Generational-decay constants  | `TRUST_GENERATION_ALPHA_NUM=230 / _DEN=256` at `trust/include/trust_types.h:419-420` | VERIFIED |
| Cancer pre-check on parent    | `trust_lifecycle_check_cancer()` at `trust/kernel/trust_lifecycle.c:579` | VERIFIED |

---

## 6. Meiosis

Section 6.4: two subjects pair, exchange a fraction of A-segments, and
produce two recombinant children.

| Concern                       | Real symbol / location                                                  | Status   |
|-------------------------------|-------------------------------------------------------------------------|----------|
| Module                        | `trust/kernel/trust_meiosis.{c,h}` (Agent 4)                            | VERIFIED |
| Paper-spec entry point        | `trust_meiosis()` (`EXPORT_SYMBOL_GPL` at `trust/kernel/trust_meiosis.c:448`) | VERIFIED |
| Userspace-id wrapper          | `trust_meiosis_request_by_id()` at `trust/kernel/trust_meiosis.c:454`   | VERIFIED |
| Active-bond counter           | `trust_meiosis_active_bonds()` at `trust/kernel/trust_meiosis.h:128`    | VERIFIED |
| Lifetime count                | `trust_meiosis_count()` at `trust/kernel/trust_meiosis.h:127`           | VERIFIED |
| ioctl                         | `TRUST_IOC_MEIOSIS` (NR=132, RW) at `trust/include/trust_ioctl.h:431`   | VERIFIED |
| sysfs counters                | `/sys/kernel/trust/meiosis_active_bonds`, `/sys/kernel/trust/meiosis_count` | VERIFIED |
| libtrust userspace wrapper    | `trust_meiosis_request()` (LIBTRUST_1.4) at `trust/lib/libtrust.c:1292` | VERIFIED |

The pre-S50 doc claimed `TRUST_IOC_MEIOSIS_REQUEST` and
`TRUST_IOC_MEIOSIS_ACCEPT` as separate ioctls; in shipping code there is a
single `TRUST_IOC_MEIOSIS` whose request struct carries both pids. See
Deviations §D.

---

## 7. Cancer Detection

Section 6.5: any subject that exceeds its mitosis-rate budget within
`cancer_threshold_ms` is flagged as cancerous and apoptosed.

| Concern                       | Real symbol / location                                                  | Status   |
|-------------------------------|-------------------------------------------------------------------------|----------|
| Per-subject probe             | `trust_lifecycle_check_cancer()` at `trust/kernel/trust_lifecycle.c:579` | VERIFIED |
| 16-slot sliding window table  | `g_cancer_table` at `trust/kernel/trust_lifecycle.c:1242`                | VERIFIED |
| Threshold (mutable, sysfs)    | `g_cancer_threshold_ms` at `trust/kernel/trust_lifecycle.c:1246`         | VERIFIED |
| Threshold default             | `TRUST_CANCER_THRESHOLD_MS_DEFAULT = 100` at `trust/kernel/trust_lifecycle.h:94` | VERIFIED |
| Detection counter (atomic)    | `g_cancer_detections` at `trust/kernel/trust_lifecycle.c:1249`           | VERIFIED |
| sysfs node (RW threshold)     | `/sys/kernel/trust/cancer_threshold_ms`                                  | VERIFIED |
| sysfs node (RO counter)       | `/sys/kernel/trust/cancer_detections`                                    | VERIFIED |
| Apoptosis action              | `trust_apoptosis_request()` at `trust/kernel/trust_lifecycle.c:1335`     | VERIFIED |

Note: the pre-S50 doc claimed the threshold default was `5000` and that
the action was `trust_apoptose() / trust_quarantine()`. The real default
is `100` ms (see `trust_lifecycle.h:94`) and the kernel symbol is
`trust_apoptosis_request()`. The userspace `trust_quarantine()` lives
only in `libtrust` (`trust/lib/libtrust.c:1097`), not kernel-side. See
Deviations §E.

---

## 8. ISA — 6 Families

Per Section 7, the Trust ISA spans 6 families. The shipping enum keeps
the historical name `META` (the paper uses `FLOW`); see Deviations §F.

| Family (code) | Family (paper) | Purpose                                              | Status   |
|---------------|----------------|------------------------------------------------------|----------|
| AUTH          | AUTH           | Authority-state mutation, proof issuance/consumption | VERIFIED |
| TRUST         | TRUST          | Score arithmetic, decay, scoring policy              | VERIFIED |
| GATE          | GATE           | Threshold tests, hysteresis, lockdown engagement     | VERIFIED |
| RES           | RES            | Resource accounting, quotas, budgets                 | VERIFIED |
| LIFE          | LIFE           | Mitosis, meiosis, apoptosis, quarantine, rescue      | VERIFIED |
| META          | FLOW           | System-wide meta operations / scheduling             | VERIFIED (renamed; see Deviations §F) |

Implementation: family constants `TRUST_ISA_FAMILY_*` at
`trust/include/trust_types.h:52-58`; dispatcher in
`trust/kernel/trust_dispatch.c`. The opcode space is identical regardless
of the META/FLOW name — it is purely a label divergence.

---

## 9. APE Pool Isolation

Section 4.4 mandates APE memory live in a ring strictly more privileged
than the kernel's own data. On Linux x86_64 we approximate this in
software:

| Mechanism                   | Real symbol / location                                          | Status   |
|-----------------------------|------------------------------------------------------------------|----------|
| Dedicated subject-class table| APE entries live in their own table inside `trust_ape.c`         | VERIFIED |
| Per-entry lock              | `entry->lock` (see `trust_ape_consume_proof_v2`)                 | VERIFIED |
| Atomic consume-and-zero      | `trust_ape_consume_proof_v2()` at `trust/kernel/trust_ape.c:815` | VERIFIED |
| Software-only ring-2 model  | Documented; see Deviations §G                                    | VERIFIED |

---

## 10. Theorems 1, 2, 4, 5, 6 as Runtime Invariants

Per Section 8, the paper proves five operational theorems. Each is
monitored at runtime in `trust/kernel/trust_invariants.c` and exposed
via sysfs.

| Theorem | Statement (paraphrased)                                          | Counter / sysfs                                       | Status   |
|---------|------------------------------------------------------------------|-------------------------------------------------------|----------|
| 1       | Consumed proof is unforgeable; consume is total + idempotent     | `/sys/kernel/trust/theorem1_violations`               | VERIFIED |
| 2       | Generational decay is monotone                                   | `/sys/kernel/trust/theorem2_violations`               | VERIFIED |
| 4       | Authorisation is conservative (caps superset of request)         | `/sys/kernel/trust/theorem4_violations`               | VERIFIED |
| 5       | Cancer detector terminates within `cancer_threshold_ms`          | `/sys/kernel/trust/theorem5_violations`               | VERIFIED |
| 6       | Meiosis preserves total population A-segment entropy (within e)  | `/sys/kernel/trust/theorem6_violations` (mirrored from `trust_authz_theorem6_violations()`) | VERIFIED |

Sysfs registration: `trust_invariants.c:307-331`. A non-zero counter is
a hard ops alarm — wire it to the cortex veto path.

---

## 11. Authorization Decision

Section 4.5 defines the central decision predicate.

| Concern                       | Real symbol / location                                                  | Status   |
|-------------------------------|-------------------------------------------------------------------------|----------|
| Entry point                   | `trust_authz_check()` at `trust/kernel/trust_authz.c:205`               | VERIFIED |
| Header declaration            | `trust/kernel/trust_authz.h:81`                                          | VERIFIED |
| Failure-predicate bitmask     | `trust/kernel/trust_authz.h:35` (header comment)                         | VERIFIED |
| Theorem-4 violation increment | `g_theorem4_violations` (incremented inside `trust_authz_check`)         | VERIFIED |

---

## 12. Generational Decay

Section 5.5: maximum admissible score decays geometrically with
generation `g`.

| Concern                       | Real symbol / location                                                  | Status   |
|-------------------------------|-------------------------------------------------------------------------|----------|
| alpha numerator (fixed-point) | `TRUST_GENERATION_ALPHA_NUM = 230` at `trust/include/trust_types.h:419` | VERIFIED |
| alpha denominator             | `TRUST_GENERATION_ALPHA_DEN = 256` at `trust/include/trust_types.h:420` | VERIFIED |
| Max generation depth          | `TRUST_GENERATION_MAX = 16` at `trust/include/trust_types.h:421`        | VERIFIED |
| Applied at mitosis            | `trust/kernel/trust_lifecycle.c:386` (S_max formula)                    | VERIFIED |
| Theorem-2 enforcement         | `trust_invariants.c` (theorem2 counter)                                 | VERIFIED |

Note: the pre-S50 doc cited a per-subject `A_DECAY_ALPHA` chromosome
slot. No such slot exists; alpha is a system-wide constant (the chromosome
slot at index 4 is `CHROMO_A_MEMORY`, not decay alpha). See Deviations §H.

---

## 13. AI Cortex / Dynamic Hyperlation Surface

Section 9 of the paper. The cortex is realised in userspace as
`ai-control/cortex/dynamic_hyperlation.py` and exposed via FastAPI.

| Endpoint                                  | Returns                                                            | Status   |
|-------------------------------------------|--------------------------------------------------------------------|----------|
| `GET /cortex/hyperlation/state`           | Hyperlation snapshot (subjects + global), filterable by class/state/pid | VERIFIED (`ai-control/cortex/api.py:714`) |
| `GET /cortex/hyperlation/subject/{sid}`   | Single-subject hyperlation view                                     | VERIFIED (`ai-control/cortex/api.py:740`) |
| `GET /cortex/hyperlation/theorems`        | Per-theorem violation counters                                      | VERIFIED (`ai-control/cortex/api.py:772`) |

Module: `ai-control/cortex/dynamic_hyperlation.py`. The slot enum
seeds the three foundational hypotheses (next section).

---

## 14. The Three Foundational Hypotheses

Each is anchored as a named slot in `HypothesisSlot` so a future audit
can grep the enum and confirm each is reachable.

| Hypothesis                                              | Real symbol                  | Citation                                                  | Status   |
|---------------------------------------------------------|------------------------------|-----------------------------------------------------------|----------|
| H1: Authority is dynamic, not static (metabolic trust)  | `HYP_DYNAMIC_AUTHORITY`      | `ai-control/cortex/dynamic_hyperlation.py:168, 175`       | VERIFIED |
| H2: Trust is biological, not cryptographic              | `HYP_BIOLOGICAL_TRUST`       | `ai-control/cortex/dynamic_hyperlation.py:169, 176`       | VERIFIED |
| H3: Apoptosis is required for safety                    | `HYP_APOPTOTIC_SAFETY`       | `ai-control/cortex/dynamic_hyperlation.py:170, 177`       | VERIFIED |

Aggregate slot list: `HYPOTHESIS_SLOTS` at
`ai-control/cortex/dynamic_hyperlation.py:178`.

---

## 15. Deviations from paper

Each deviation below is a place where the shipping symbol name does NOT
match the paper's terminology. They are listed so future audits can
mechanically translate paper language to grep-friendly identifiers.

### A. Reconfigurable hash `H_cfg(n)` -> two functions

| Paper                | Code                                                            |
|----------------------|------------------------------------------------------------------|
| `H_cfg(n)(...)`      | `derive_hash_cfg()` + `apply_reconfigurable_hash()` (split pair) |

The shipping code separates *deriving the configuration* (per-subject,
nonce-bound) from *applying the permutation*. There is no single function
literally named `cfg_hash` or `Hcfg`.

### B. A/B-segment slot names

The paper uses domain-flavoured names like `A_AUTH_PROFILE`,
`A_GATE_THRESHOLD`, `A_DECAY_ALPHA`, `B_LINEAGE_ROOT`,
`B_BIRTH_GENERATION`, `B_REPRODUCTION_KEY`. None of these exist as code
symbols. The shipping code uses behaviour-flavoured names like
`CHROMO_A_ACTION_HASH`, `CHROMO_A_TOKEN_BALANCE`, `CHROMO_A_TRUST_STATE`,
`CHROMO_B_BINARY_HASH`, `CHROMO_B_LIBRARY_DEPS`, `CHROMO_B_FUSE_STATE`.
The translation is per-section above; treat the doc tables in §3 as
authoritative.

### C. Sex-determination evaluator

| Paper                       | Code                                                            |
|-----------------------------|------------------------------------------------------------------|
| `trust_conf_eval(E, t)`     | inline computation in `trust_chromosome.c` against `CHROMO_CONFORMANCE_THETA` |
| `trust_assign_sex(...)`     | inline assignment to `chromo->sex` + `subject->sex` mirror       |
| Threshold `theta`           | `trust_sex_threshold_get()` (per-mille, default 700/1000)        |

The evaluator and the assignment are not named functions in the kernel
tree; they are inline inside `trust_chromosome.c` and the
`trust_lifecycle.c` mitosis path.

### D. Meiosis ioctls

| Paper                                                | Code                                  |
|------------------------------------------------------|---------------------------------------|
| `TRUST_IOC_MEIOSIS_REQUEST` + `TRUST_IOC_MEIOSIS_ACCEPT` (two-step) | single `TRUST_IOC_MEIOSIS` (NR=132) carrying both pids |

The shipping kernel implements the request and accept atomically inside
one ioctl; there is no separate accept handshake.

### E. Cancer-action verbs

| Paper                                | Code                                                         |
|--------------------------------------|--------------------------------------------------------------|
| `trust_apoptose(sid)`                | `trust_apoptosis_request(sid)` at `trust_lifecycle.c:1335`   |
| `trust_quarantine(sid)` (kernel-side)| only userspace `trust_quarantine()` exists in `libtrust.c:1097` |
| `cancer_threshold_ms` default `5000` | actual default is `100` (see `trust_lifecycle.h:94`)         |

### F. Sixth ISA family naming

| Paper            | Code                                                      |
|------------------|-----------------------------------------------------------|
| `FLOW` family    | `META` family (`TRUST_ISA_FAMILY_META`) — same opcode space |

Older sessions briefly attempted a `META -> FLOW` rename; it was
reverted. The opcode space and dispatcher are identical; the label is
the only difference.

### G. Ring -2 isolation

| Paper                             | Code                                                          |
|-----------------------------------|--------------------------------------------------------------|
| Hardware ring -2 (SMM/SGX/TDX)    | software-only: separate APE table + per-entry locks + atomic consume-and-zero |

A future SMM/SGX/TDX enclave port is open work. The runtime invariant
counters (§10) prove the abstract semantics operationally even on
commodity x86_64.

### H. Generational decay alpha

| Paper                       | Code                                                              |
|-----------------------------|-------------------------------------------------------------------|
| Per-subject `A_DECAY_ALPHA` | system-wide `TRUST_GENERATION_ALPHA_NUM/DEN` (230/256 ~= 0.898)   |

There is no per-subject alpha chromosome slot. Index 4 in the A-segment
table is `CHROMO_A_MEMORY`, not a decay coefficient.

### I. Authority-state accessors

| Paper                                | Code                                                          |
|--------------------------------------|---------------------------------------------------------------|
| `trust_state_get_C/S/P/G/L(sid, *)`  | macros `authority_C/S/P/G/L(s)` in `trust/include/trust_types.h:596-612` + ioctl `TRUST_IOC_AUTHORITY_STATE` (NR=133) |

There are no `trust_state_get_*` accessor functions; userspace reads the
24-byte `trust_authority_state_t` wire form via the single ioctl.

### J. RISC-V FPGA proof-of-concept

The paper specifies a **RISC-V FPGA proof-of-concept** for the trust ISA.
This project ships an **x86_64 software ISA dispatched by `trust.ko`**,
not RISC-V silicon. Acceptable because:

1. The paper's proofs (Theorems 1, 2, 4, 5, 6) are stated over the
   abstract ISA semantics, not over a specific RTL. The software
   dispatcher is a faithful reproduction of those semantics — the
   runtime invariant counters in §10 prove it operationally.
2. The FPGA PoC is the paper's reference *hardware* implementation;
   this repo is the reference *Linux* implementation — a complementary
   artefact.

---

## 16. APE configuration history

Timeline of the 94,371,840-configuration reconfigurable-hash construct,
kept here so future reviewers (peer-review readers and on-boarding
engineers) can reconstruct the archaeology without spelunking git
reflogs. Citations are to memory session files
(`memory/session*.md`) and the archaeology report at
`docs/ape-regression-archaeology.md`.

- **S38-S47 — pre-94M baseline.** APE proof chain shipped with a
  3-algorithm SHA cycle (SHA-256 / BLAKE2b-256 / SHA3-256) selected by
  `proof[0..3] % 3`. `TRUST_HASH_CFG_COUNT = 3` in `trust_types.h`.
  No perm table, no window/mask/rot fields. Paper claim of 94M
  configurations was aspirational relative to code at this point.
- **S48 — 94M implementation landed.** Agent 1 rewrote `trust_ape.c` to
  add `ape_perm_table[720][8]`, `heap_permute_init()`, `decode_cfg()`,
  `apply_reconfigurable_hash()`, `compute_proof_v2()`, and the
  `BUILD_BUG_ON(APE_CFG_TOTAL != 94371840ULL)` compile-time assert.
  Paper-vs-code structural bisimulation closed.
- **S49→S50-era regression.** A working-tree manipulation (not a commit
  — an unsynced edit) reverted `trust_ape.c` to the pre-S48 3-algo stub
  while leaving `trust_ape.h` advertising `APE_CFG_TOTAL = 94,371,840`.
  Result: 7-order-of-magnitude paper-vs-code gap. Root cause documented
  in `docs/ape-regression-archaeology.md` (Agent S, S74).
- **Pre-S74 HEAD (prior to faf6d8e).** `trust_ape.c` was 655 LOC,
  header still advertised 94M, `apply_reconfigurable_hash` did not
  exist, and `docs/roa-conformance.md` claimed `apply_reconfigurable_hash()
  at trust_ape.c:224` — a row that pointed at a non-existent symbol.
  Research-D §0.3 flagged as REGRESSED-or-DOC-DRIFT; S74 Agent 10
  triaged.
- **S74 (faf6d8e — 2026-04-20).** Recovery from dangling-stash commit
  `9b04ca1` (end-of-S49 checkpoint the original Agent 1 work lived on).
  `trust_ape.c` restored to 1260 LOC (+605 vs stub); 12 target-symbol
  matches (was 0). `BUILD_BUG_ON` re-armed to prevent silent
  re-regression. Paper-vs-code bisimulation re-closed at the structural
  layer.
- **S75 (Agent E).** `SHA-256(trust.ko .text)` folded into the APE
  proof input via the attestation quine
  (`trust/include/trust_attest_quine.h`, included at
  `trust/kernel/trust_ape.c:56`). This raises the adversary's model
  requirement from "predict cfg(n)" to "predict cfg(n) AND the
  kernel-module code image is unchanged".
- **S78 (Dev E — this commit).** Docs reconciled to match the shipping
  code: (a) `docs/roa-conformance.md` §2 line numbers point at real
  post-recovery symbols (previous rows claimed `trust_ape.c:224` for
  `apply_reconfigurable_hash` and `trust_ape.c:815/1038` for the v2/v1
  consume entry points — post-recovery, the symbols live at 225 /
  825 / 1067 respectively); (b) header comment in `trust/kernel/trust_ape.h`
  states the implementation reality, references §SCP eq.(1), cites the
  S74 recovery SHA, and calls out the `S_n` behavioral-state binding as
  the genuine moat per research-D §3.1; (c) `docs/paper-vs-implementation.md`
  row 4 advanced from REGRESSED-or-DOC-DRIFT to FAITHFUL.

Related references:

- `docs/ape-regression-archaeology.md` — pre-recovery forensics
  (Agent S, S74) establishing the regression was a working-tree
  manipulation, not aspirational scaffolding.
- `docs/ape-regression-triage.md` — the S74 Agent 10 triage report.
- `memory/session74_research_architecture_build.md` Finding #10 — the
  entry point into the research-D crypto audit.
- `memory/session75_8agent_s75_punchlist.md` — APE recovery consolidation.
- `memory/session76_5agent_arc.md` — APE 94M/3 deferred section (this
  doc reconciliation was carried forward as a moat-credibility item).

The `BUILD_BUG_ON(APE_CFG_TOTAL != 94371840ULL)` assert at
`trust/kernel/trust_ape.c:528` is the mechanical guarantee that any
future session weakening the macro will fail the kernel build. CI
should additionally `grep -c apply_reconfigurable_hash trust/kernel/trust_ape.c`
and fail on zero, per the last remediation item in
`docs/ape-regression-archaeology.md`.

---

## Citation

> Roberts, Eli, Leelee. *Root of Authority*. Zenodo record 18710335.
> DOI: [10.5281/zenodo.18710335](https://doi.org/10.5281/zenodo.18710335).
