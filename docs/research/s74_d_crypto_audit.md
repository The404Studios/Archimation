# S74-D — Cryptographic Primitive Audit: Self-Consuming Proofs (APE)

**Agent:** S74 Research Agent D of 10 (parallel)
**Axis:** Cryptographic primitive survey + APE novelty/gap analysis
**Mode:** RESEARCH ONLY — no source edits
**Subject:** Authority Proof Engine (`trust/kernel/trust_ape.c`), Root of Authority paper, Roberts / Eli / Leelee, Zenodo 18710335, DOI 10.5281/zenodo.18710335

---

## 0. Executive Summary

### 0.1 The one-line claim the paper makes about APE

> "Proofs are self-consuming: Pn+1 = Hcfg(n)(Pn || Rn || SEED || Nn || Tn || Sn), and Pn is destroyed atomically on use. Hardware (Ring -2) enforces write-once SEED and read-and-zero PROOF registers; software emulation uses spinlocks and `memzero_explicit`."

### 0.2 What APE actually looks like in the tree

- **File:** `trust/kernel/trust_ape.c` (656 LOC shipping today; the paper-conformance doc references an 815-LOC `consume_proof_v2` that is **not present** in the current file — S74 regression flag)
- **SEED provenance:** `get_random_bytes(local_seed, 32)` at `trust_ape.c:297` — Linux CRNG (ChaCha20-based since 5.17), **NOT the TPM RNG**, despite `trust_attest.c` already binding a TPM chip at module init
- **SEED lifetime:** Written into `entry->state.seed[32]`; never zeroed during subject lifetime; zeroed with `memzero_explicit` only on `trust_ape_destroy_entity()` (trust_ape.c:431). SEED is **re-read on every `consume_proof` call** (trust_ape.c:492), so "write-once, read-never" is an aspiration of the hardware spec, not a property of the software emulation.
- **PROOF destruction:** `memzero_explicit(entry->state.proof, 32)` + `proof_valid = 0` at trust_ape.c:488 — this is the one property that IS honored in software
- **Hash family:** SHA-256 / BLAKE2b-256 / SHA3-256 selected via 2-bit selector `proof[0..3] % 3` (trust_ape.c:52-58). The paper claims 94,371,840 reconfigurable hash variants (720 perms × 256 windows × 16 masks × 32 rots — `trust_ape.h:44-52`); the shipping code implements **3** of them (`TRUST_HASH_CFG_COUNT = 3` at `trust_types.h:276`). **S74 regression flag.**
- **Security analysis:** Theorem-3 chi-square runtime witness in `trust_ape_markov.c` (N=10000, 256-bin χ² against SHA-256 output — a point-test, never fails load)
- **Formal analysis:** Paper asserts 3 theorems; no machine-checked proof; no IACR ePrint submission located

### 0.3 Top-level comparison table

| Primitive | Year | Shape overlap with APE | Hardware requirement | Novelty delta of APE |
|---|---|---|---|---|
| **One-time pad** (Shannon) | 1949 | LOW — OTP consumes *key*, APE consumes *proof*; APE has no secret-key semantics | None (symmetric key delivery) | APE binds proof to action request Rn; OTP is for message confidentiality, APE is for authorization |
| **Lamport one-time signature** | 1979 | HIGH — one key pair per signature, key material destroyed on use | None (hash-only) | APE is a proof *chain* not a signature; APE output is not verifiable by a third party without replaying chain |
| **Merkle hash tree** | 1979 | MEDIUM — tree of hashes, but APE is a linear chain | None | APE's linear chain is cheaper but loses logarithmic proof-size; APE also has no public-verifier role |
| **Lamport hash chain** (S/Key) | 1981 | **VERY HIGH** — Hn = H(Hn-1), reveal-in-reverse, each reveal consumes one link | None | APE advances chain on use (destroys Pn after producing Pn+1); Lamport advances by revealing a pre-computed link. Inverse direction of consumption. |
| **One-time pads (Shannon)** | 1949 | LOW-MED | None | See above. |
| **HMAC (Bellare-Canetti-Krawczyk)** | 1996 | LOW — symmetric MAC, verifier holds key | None | APE has no key-holding verifier; the SEED is secret but never reveals |
| **PayWord hash chain** (Rivest-Shamir) | 1996 | HIGH — pre-computed chain revealed link-by-link | None | APE chain is not pre-computed; each new link is computed from the just-consumed one |
| **Time-lock puzzle** (RSW) | 1996 | LOW — proof-of-elapsed-time | None (trusted setup for modulus) | Different threat model; APE is not about time |
| **Proof-carrying code** (Necula) | 1997 | MEDIUM — proofs attached to computations | None | APE proofs are not formal proofs; they are entanglement witnesses |
| **Forward-secure signatures** (Bellare-Miner) | 1999 | MEDIUM — signing key evolves, old signatures still verifiable | None | APE proofs bind to history; forward-secure sigs preserve past validity under future key compromise (different invariant) |
| **Proof-carrying authentication** (Appel-Felten) | 1999 | MEDIUM — carries authorization derivations | None | APE is not derivation-explicit; it is entanglement-only |
| **VRF** (Micali-Rabin-Vadhan) | 1999 | MED — unique commitment to output before reveal | None | APE has no public verifiability; VRF outputs are publicly verifiable |
| **Schnorr-like Fiat-Shamir proofs** | 1989 / 1986 | LOW — non-interactive ZK proof | None | APE is not ZK; chain leaks state across verifiers |
| **Sponge / Keccak-SHA3** (Bertoni et al.) | 2007-2015 | **HIGH** — absorb/squeeze lifecycle fits APE's "consume proof → absorb → squeeze new proof" perfectly | None | APE could be rewritten as a sponge state advance; currently implemented as stateless SHA-256 calls |
| **One-time programs** (Goldwasser-Kalai-Rothblum) | 2008 | MEDIUM — one-shot evaluation | **Hardware tokens OR OT required** | APE claims one-shot proof consumption without hardware tokens; software emulation is explicitly "best effort" |
| **XMSS / SPHINCS+ (Lamport-composed)** | 2011-2015 | HIGH — many one-time signatures glued into stateful/stateless many-time | None (hash-only) | APE is 1 chain per subject; XMSS is Merkle-of-Lamport composition; PQ angle is **untapped** for APE |
| **Puncturable encryption** (Green-Miers) | 2015 | MEDIUM — keys can be punctured at specific points | None (pairings in original construction) | APE's "destroy on use" resembles puncturing-on-use; APE doesn't preserve verifiability of unpunctured points |
| **Hybrid Argon2id + CRNG reseed** (IRTF CFRG modern) | 2023-2026 | LOW | None | APE's seed comes from Linux CRNG; opportunity to layer TPM2 + Argon2id-stretched seed |

**Takeaway of the table:** APE is most structurally similar to **Lamport hash chains (1981) + PayWord (1996) + sponge constructions (2007-2015)**, but with a novel combination: linear chain + hash-algorithm reconfiguration (mixing) + destruction semantics + binding to application-semantic SEED and chromosome checksum.

---

## 1. APE as implemented: structural snapshot

This section describes what is actually in the tree, distinct from what the paper claims.

### 1.1 The construction

```
Create entity (trust_ape.c:275-398):
  local_seed  = get_random_bytes(32)           [trust_ape.c:297]
  nonce       = get_random_bytes(8)             [trust_ape.c:301]
  ts          = trust_get_timestamp()           [trust_ape.c:304]
  init_data   = local_seed || nonce || ts       [48 bytes total]
  P0          = SHA-256(init_data)              [trust_ape.c:309]
  entry.state.seed  = local_seed                [trust_ape.c:375]
  entry.state.proof = P0                        [trust_ape.c:382]
  entry.state.hash_cfg = P0[0..3] % 3           [trust_ape.c:386, derive_hash_cfg]
  local_seed, P0 are memzero_explicit'd          [trust_ape.c:392-393]

Consume proof (trust_ape.c:454-568):
  SPINLOCK g_trust_ape.lock
    entry = ape_find(subject_id)                [O(1) hash index]
    SPINLOCK entry->lock
  UNLOCK g_trust_ape.lock
    consumed_proof = entry.state.proof          [trust_ape.c:486]
    memzero_explicit(entry.state.proof, 32)      [trust_ape.c:488]  <<< "destroy on read"
    entry.state.proof_valid = 0
    seed_copy = entry.state.seed                [trust_ape.c:492]   <<< SEED IS NOT DESTROYED
    entry.state.nonce++                         [trust_ape.c:493]   <<< monotonic
  UNLOCK entry->lock
  hash_cfg  = consumed_proof[0..3] % 3          [trust_ape.c:504]   <<< reconfig derivation
  hash_input = consumed_proof || request || seed_copy || nonce || ts  (up to 336 bytes)
  Pn+1 = Hcfg(n)(hash_input)                    [trust_ape.c:528]   <<< new proof
  consumed_proof, seed_copy, hash_input all zeroed
  SPINLOCK g_trust_ape.lock + entry->lock
    entry.state.proof       = Pn+1
    entry.state.proof_valid = 1
    entry.state.chain_length++
    entry.state.hash_cfg    = derive_hash_cfg(Pn+1)
  UNLOCK
  memzero_explicit(new_proof)
```

### 1.2 What "destroyed on read" means in memory-hierarchy terms

- The 32-byte `proof` field in `trust_proof_state_t` is **overwritten in place** via `memzero_explicit` (trust_ape.c:488). `memzero_explicit` is the kernel API that the compiler is forbidden from optimizing away (contrast with `memset`, which can be). See `include/linux/string.h` and `lib/string.c`.
- The entry is NOT freed; the slot is reused on next create-or-rotate.
- **CPU caches:** `memzero_explicit` does not issue `CLFLUSH` or `CLFLUSHOPT`; the value survives in L1 dcache until naturally evicted. An attacker with kernel memory read (e.g., via speculative side-channel or IORESOURCE_MEM leak) could potentially recover the consumed value from cache during a short window.
- **Kernel page tables:** the `trust_ape_entry_t` array is in kernel .bss / slab pages. There is no memory-encryption binding (no AMD SME, no Intel TME-MK key-tagging). On CoW VM snapshot or hibernation dump, past proofs could be recovered from the swapfile. `trust_ape.c` does not mark the array `__nosave` or mlock it.
- **Register clearing:** when `compute_proof` returns, `new_proof[32]` resides on the kernel stack; `memzero_explicit(new_proof, 32)` is called (trust_ape.c:566). CPU registers that held partial SHA state are not explicitly cleared; clobbering them depends on the compiler's register allocation of subsequent code.

**Verdict on "destroyed on read":** The field-overwrite is rigorous; the larger system-level claim (no copies leak) is **not fully defended** by the current implementation. This is acceptable if the Ring-(-2) hardware claim in the paper is assumed, but the software emulation has at least 3 residual leak paths: L1/L2/L3 cache, register file, hibernation image.

### 1.3 SEED provenance — the critical detail

The paper describes SEED as a **write-once identity register** set at entity birth and never readable thereafter. The software emulation:

1. Allocates 32 bytes via `get_random_bytes(local_seed, 32)` — Linux CRNG (ChaCha20-based since 5.17; the older pre-5.17 path is `random.c`'s blake2s extraction from entropy pool)
2. Copies into `entry->state.seed` at trust_ape.c:375
3. **Re-reads the seed on every `consume_proof` call** at trust_ape.c:492 to include in the hash input
4. Zeroes only on `trust_ape_destroy_entity` at trust_ape.c:431

This means:

- SEED is not write-once; it is in kernel memory and the `memcpy` at line 492 touches it on every proof consumption. An attacker with kernel memory read can exfiltrate SEED during the consume window (spinlock-held for microseconds).
- SEED is not hardware-bound. It is not TPM-backed. It is not sealed to any PCR.
- SEED entropy is Linux CRNG quality, which is cryptographically good post-5.17 but derives from hardware entropy sources that may not meet FIPS 140-3 SP 800-90B certification unless the kernel is configured with `CONFIG_RANDOM_TRUST_CPU=n` AND `CONFIG_RANDOM_TRUST_BOOTLOADER=n` AND adequate jitter entropy is present.

**The paper's claim that SEED is "physically write-once" is a hardware aspiration. The software emulation is honest about this (trust_ape.c:3-8 explicitly says so: "In hardware, the SEED register is physically write-once and the PROOF register is atomic read-and-zero. We emulate these semantics using spinlocks and explicit state flags.").**

### 1.4 Adversary model

The paper does not explicitly enumerate the adversary. Deduced from the construction:

| Adversary tier | Can they break APE? | Why / why not |
|---|---|---|
| **Userspace process without CAP_SYS_ADMIN** | No | Cannot read `/dev/trust`'s internal state; ioctl interface returns only the current proof value on consume |
| **Userspace process with CAP_SYS_ADMIN** | Yes (trivially, via `/dev/mem`) | Can read kernel memory directly — SEED and PROOF are both visible. Trust.ko does not defend against a peer with kernel-read. |
| **Kernel-resident attacker (rootkit, malicious LKM)** | Yes | Can read `g_trust_ape.entries[]` and observe SEED+PROOF in place, forge consume-advance sequences |
| **Offline-disk attacker (encrypted-FDE bypass, hibernation image)** | Potentially | If the system hibernated between proof creates and shutdown, the hibernation image in swap could contain live SEED values. APE does not mlock or `__nosave` its state. |
| **Side-channel attacker (Spectre-v2, L1TF, MDS)** | Potentially | The `consume_proof` path reads SEED under spinlock; speculative execution could exfiltrate bytes into cache lines. No explicit speculation barriers around the SEED memcpy. |
| **Out-of-tree kernel module (DKMS driver)** | Yes | Shares kernel address space; no PKRU, no Intel MKTME keying domain separation |
| **SMM / Ring -2 attacker** | Yes | Above Ring 0; only actual hardware APE would defend |

**Fundamental framing:** APE is designed to defend against **misbehaving but non-root userspace subjects** who hold a `trust_subject_id` and try to replay or forge authority. It is **not designed** to defend against a peer kernel resident. This is reasonable: the kernel is the TCB.

### 1.5 The chi-square runtime witness

`trust_ape_markov.c` (222 LOC) implements a **point-test** for Theorem 3 (Reconfiguration Unpredictability):

- N = 10,000 random inputs, each fed through SHA-256 only (not the composite chain — the composite is inaccessible from this TU per Session 58 lock)
- 256-bin histogram of output bytes (320,000 observations / 256 bins → expected = 1,250 per bin)
- Chi-square in integer math, threshold = 300 (roughly p<0.005 at 255 d.o.f.)
- Logs verdict at module load; never fails load

**Honest caveats in the code itself** (`trust_ape_markov.c:22-29`):
> "We CANNOT call apply_reconfigurable_hash() directly... Using SHA-256 directly is a strict LOWER-BOUND on the chain's mixing — if SHA-256 alone fails uniformity at our threshold, the composite chain certainly does. A passing SHA-256 test does NOT prove the composite is uniform."

**Assessment:** This is a boot-time sanity check for the crypto subsystem, not a Theorem-3 validation. A hostile crypto-API stub (e.g., SHA returning zeros) would be caught; a hostile reconfiguration logic (e.g., `derive_hash_cfg` biasing toward weak configs) would NOT be caught.

---

## 2. Cryptographic primitive survey

For each primitive: (a) year / author / function, (b) threat model, (c) hardware assumptions, (d) overlap with APE, (e) delta.

### 2.1 One-time pads — Shannon 1949

**(a)** Claude Shannon, *Communication Theory of Secrecy Systems*, Bell System Tech. J. 28(4):656-715, 1949. Defines the OTP / Vernam cipher; proves perfect secrecy when key is uniform random, at least as long as the message, and used exactly once.

**(b)** Threat model: a computationally unbounded passive eavesdropper. Active attackers (modification, replay) are NOT defended.

**(c)** Hardware: none. Requires physical one-way key-delivery channel.

**(d) Overlap with APE:** LOW. OTP consumes the **key**; APE consumes the **proof**. The shared keyword "consumed on use" is misleading. In an OTP, the key is a shared secret; in APE, the proof is a per-subject state shown to the verifier (the kernel). APE has no confidentiality goal.

**(e) Delta:** APE's "consume" is state advancement for authorization, not key destruction for confidentiality.

### 2.2 Lamport one-time signatures — Lamport 1979

**(a)** Leslie Lamport, *Constructing Digital Signatures From a One Way Function*, SRI Tech Rept CSL-98, 1979. Builds a signature scheme from a hash function only: to sign one bit, reveal one of a pre-committed pair of hash preimages. Each key pair signs exactly one message; using again reveals too much.

**(b)** Threat model: chosen-message attack with one message budget.

**(c)** Hardware: none; hash-only.

**(d) Overlap with APE:** HIGH. Both have the "use-once-then-dead" property. Both rely only on hash one-wayness. Both destroy key material on use.

**(e) Delta:** Lamport signatures produce a PUBLIC VERIFIABLE artifact; APE produces an internal state advance. Lamport's output is a vector of preimages visible to all; APE's consumed proof is hidden from all (kernel-private). Lamport commits to one message; APE advances by one action and continues.

### 2.3 Merkle trees — Merkle 1979

**(a)** Ralph Merkle, *A Certified Digital Signature*, CRYPTO '89 (Lecture Notes in CS 435), pp. 218-238. (Originated in his 1979 PhD thesis.) Tree-structured hash accumulators; authentication path = O(log N) hashes.

**(b)** Threat model: second-preimage on underlying hash.

**(c)** Hardware: none; hash-only.

**(d) Overlap with APE:** MEDIUM. Both accumulate state via hashing. Merkle is tree-structured (logarithmic authentication path); APE is linear chain (O(1) per step, but O(N) chain length for full history).

**(e) Delta:** Why not a tree? A tree would let APE show "proof is on the committed chain at step N" in log(N) hashes — but APE does not have external verifiers checking chain membership; it is kernel-internal state. Linear chain is sufficient. However, if APE ever exposes chain commitments externally (e.g., for audit logs or forensic replay), Merkle accumulation would be the right primitive.

### 2.4 Lamport hash chains / S/Key — Lamport 1981

**(a)** Leslie Lamport, *Password Authentication with Insecure Communication*, Communications of the ACM 24(11):770-772, November 1981. Pre-compute Hn(seed) for large N; reveal in reverse order (Hn-1, Hn-2, ...); verifier checks H(revealed) = last-accepted. Basis for S/Key (RFC 1760, 1995) and OTP systems.

**(b)** Threat model: eavesdropping adversary observing password in flight. Each revelation is useless for future auths because inverting H is hard.

**(c)** Hardware: none; hash-only.

**(d) Overlap with APE:** **VERY HIGH — this is APE's closest cryptographic ancestor**. Same basic shape: hash-chain of size N, one link consumed per auth, after N uses the chain is exhausted.

**(e) Delta:** 
- **Direction of chain:** Lamport pre-computes Hn(seed), Hn-1(seed), ..., H0(seed) and reveals in reverse (Hn-1 first, H0 last). The server holds the most-recently-verified. APE advances forward: Pn+1 = H(Pn || context). The kernel holds the current "head" and computes the next.
- **Who holds seed:** In Lamport, the client holds seed; the server holds Hn(seed). In APE, the kernel holds both SEED and Pn; clients hold nothing.
- **Chain lifetime:** Lamport exhausts after N uses; APE chain is unbounded (no chain-length cap in trust_ape.c).
- **Application binding:** Lamport links are independent of any request semantic; APE links bind to request Rn, nonce Nn, timestamp Tn, and chromosome checksum Sn.

**This is where APE's novelty is strongest.** Lamport-style chains do not bind to per-action semantics; APE does. A replay of a past APE proof would fail not because the chain is known (it might be) but because the context (Rn, Nn) will differ.

### 2.5 HMAC — Krawczyk-Bellare-Canetti 1996

**(a)** Mihir Bellare, Ran Canetti, Hugo Krawczyk, *Keying Hash Functions for Message Authentication*, CRYPTO '96 (LNCS 1109), pp. 1-15. Also RFC 2104 (1997). Construction: HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m)). Provides MAC-security from hash-security under weaker assumptions than keyed-hash.

**(b)** Threat model: chosen-message forgery with key-less adversary.

**(c)** Hardware: none.

**(d) Overlap with APE:** LOW-MEDIUM. APE hashes (proof || request || seed || ...) which is closer to keyed-hash than HMAC (no ipad/opad structure). Under the random-oracle model the construction is secure; under the PRF assumption the paper gives, it is less rigorous than HMAC.

**(e) Delta:** The SEED plays the role of a secret key, but APE does not use HMAC's nested hashing. APE is vulnerable in principle to length-extension on non-Merkle-Damgard hashes (SHA-3, BLAKE2 are resistant; SHA-2 is extensible), though the chain-structure makes length-extension attacks less impactful in practice.

### 2.6 PayWord micropayment chains — Rivest-Shamir 1996

**(a)** Ronald L. Rivest, Adi Shamir, *PayWord and MicroMint: Two Simple Micropayment Schemes*, Security Protocols Workshop 1996 (LNCS 1189), pp. 69-87. User pre-computes W0 → H(W0) = W1 → H(W1) = W2 → ... → Wn, signs Wn, reveals Wn-1, Wn-2, ... for successive micropayments. Merchant verifies each by rehashing.

**(b)** Threat model: user double-spend; merchant fraudulent claim.

**(c)** Hardware: none.

**(d) Overlap with APE:** HIGH. Same use-the-next-link-to-authenticate-next-action semantics.

**(e) Delta:**
- PayWord is pre-computed; APE is advanced on the fly
- PayWord's chain is signed at the top (Wn is committed to merchant); APE has no external signature
- PayWord links are revealed-to-merchant, useless for future payments; APE links are never revealed
- PayWord chains are bounded (length N is committed); APE is unbounded

### 2.7 Time-lock puzzles — Rivest-Shamir-Wagner 1996

**(a)** Ronald L. Rivest, Adi Shamir, David A. Wagner, *Time-lock puzzles and timed-release crypto*, MIT LCS Tech Memo MIT/LCS/TR-684, 1996. Sequential-squaring puzzle: to recover secret, compute 2^(2^t) mod N for large t; fast verification via trusted setup.

**(b)** Threat model: early decryption.

**(c)** Hardware: none; requires trusted setup for modulus N (or class-group variant).

**(d) Overlap with APE:** LOW. Different primitive — proof-of-time-elapsed.

**(e) Delta:** Not applicable. Included in the survey because the prompt mentioned it.

### 2.8 Proof-carrying code — Necula 1997

**(a)** George C. Necula, *Proof-Carrying Code*, POPL '97 (pp. 106-119). ACM. Programs carry formal safety proofs validatable by a small, trusted proof checker; checker's size determines TCB.

**(b)** Threat model: untrusted code consumer verifies safety without trusting producer.

**(c)** Hardware: none.

**(d) Overlap with APE:** MEDIUM. Both attach a "proof" to a computation. But PCC proofs are formal proofs of safety properties (via Edinburgh LF, Coq, or similar), checked by a checker. APE proofs are entanglement witnesses, checked only by rehashing under the chain.

**(e) Delta:** PCC's proofs are machine-checkable logical derivations. APE's "proofs" are cryptographic digests, not logical artifacts. Calling them "proofs" is slightly abusive — they are witnesses or tokens, not proofs in the Necula sense.

### 2.9 Forward-secure signatures — Bellare-Miner 1999

**(a)** Mihir Bellare, Sara K. Miner, *A Forward-Secure Digital Signature Scheme*, CRYPTO '99 (LNCS 1666), pp. 431-448. Signing key evolves over time via a one-way update. Compromise of the current key does not compromise signatures produced with prior keys.

**(b)** Threat model: future key compromise should not void past signatures.

**(c)** Hardware: none (the update is one-way via trapdoor/factoring).

**(d) Overlap with APE:** MEDIUM. Both evolve state over time via a one-way function.

**(e) Delta:**
- FS-Sig preserves verifiability of past signatures under future compromise; APE destroys verifiability of past proofs entirely
- FS-Sig has a public key held by all verifiers; APE has no public key
- FS-Sig is about signatures (verifiable by third parties); APE is about authorization (verified by the kernel)

### 2.10 Proof-carrying authentication — Appel-Felten 1999

**(a)** Andrew W. Appel, Edward W. Felten, *Proof-Carrying Authentication*, CCS '99, pp. 52-62. Extends PCC to authorization: client presents a formal derivation of "allowed to access X" in a logic the server trusts; server checks the derivation.

**(b)** Threat model: untrusted client presents authorization; server verifies derivation instead of trusting client.

**(c)** Hardware: none.

**(d) Overlap with APE:** MEDIUM. Both carry "proof" with an authorization request.

**(e) Delta:** PCA's proofs are logical derivations in a higher-order authorization logic (Abadi-Burrows-Lampson ABLP variants). APE's proofs are cryptographic digests. PCA is structurally richer but harder to check; APE is structurally simple but not audit-explicit.

### 2.11 Verifiable Random Functions — Micali-Rabin-Vadhan 1999

**(a)** Silvio Micali, Michael Rabin, Salil Vadhan, *Verifiable Random Functions*, FOCS '99, pp. 120-130. Pseudorandom function with a proof that the output is correctly computed from a public key; output and proof are publicly verifiable.

**(b)** Threat model: oracle tries to cheat on random output; output must be verifiable.

**(c)** Hardware: none (bilinear pairings in Boneh-Lynn-Shacham-based constructions; RSA-based in earlier ones).

**(d) Overlap with APE:** MEDIUM. VRF commits to output before reveal; APE commits to the chain's evolution.

**(e) Delta:** VRF is publicly verifiable; APE is kernel-internal. VRF has a public key; APE has only a private SEED. If APE ever needs third-party audit of proof chains (e.g., "subject S executed action A at time T"), VRF shape is the right primitive. Currently not needed.

### 2.12 Sponge constructions / Keccak / SHA-3 — Bertoni-Daemen-Peeters-Van Assche 2007-2015

**(a)** Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche, *Sponge Functions*, ECRYPT Hash Workshop 2007, and the entire Keccak submission that won NIST SHA-3 in 2012, finalized as FIPS 202 (2015). A sponge has a state of width b = r + c; input absorbed r bits at a time (XOR into state, then permute); output squeezed r bits at a time (extract, then permute).

**(b)** Threat model: preimage, collision, length-extension all resistant at stated security levels.

**(c)** Hardware: none.

**(d) Overlap with APE:** **HIGH — strong structural fit.** APE could be rewritten as a sponge where:
- Absorb: proof || request || seed || nonce || ts
- Permute (Keccak-f)
- Squeeze: new proof + new hash-cfg selector

The "consume Pn → produce Pn+1" semantic maps exactly to "squeeze state after absorbing new input." Sponge security is well-characterized (indifferentiability under RO model at min(r/2, c/2) bits).

**(e) Delta:** APE today uses **stateless SHA-256 calls** on a concatenated input buffer. A sponge implementation would:
1. Make the state intrinsic (no SEED memcpy per call)
2. Give a cleaner "permute" abstraction
3. Eliminate length-extension concerns inherent in Merkle-Damgard
4. Enable variable-length output (cfg selectors could come from extra squeeze bits)

**Concrete proposal:** sponge-native APE would replace `compute_proof` with a 1600-bit Keccak-f[1600] state per entity; absorb inputs; squeeze output. This would tighten the security story and reduce implementation footprint. The paper's aspirational "Ring -2 hardware APE" is almost certainly a sponge in disguise.

### 2.13 One-time programs — Goldwasser-Kalai-Rothblum 2008

**(a)** Shafi Goldwasser, Yael Tauman Kalai, Guy N. Rothblum, *One-Time Programs*, CRYPTO '08 (LNCS 5157), pp. 39-56. A program that can be evaluated exactly once; leaks only the single evaluation's output, nothing more.

**(b)** Threat model: program recipient tries to evaluate the program on multiple inputs.

**(c)** Hardware: **YES — hardware tokens OR oblivious transfer required**. Without hardware tokens (OTMs — one-time memory), OTP programs require OT, which has its own setup.

**(d) Overlap with APE:** MEDIUM. Both claim "use-once."

**(e) Delta:** OTP programs provably achieve one-shot with hardware tokens OR OT. APE claims one-shot WITHOUT hardware tokens — the software emulation is explicitly best-effort (vulnerable to kernel-resident attackers). APE's "one-shot" is weaker than OTP's. But APE's goals are also smaller: OTP protects program confidentiality + function integrity; APE protects authorization binding.

### 2.14 XMSS / SPHINCS+ — Buchmann-Dahmen-Hülsing 2011; Bernstein et al. 2015

**(a)** Johannes Buchmann, Erik Dahmen, Andreas Hülsing, *XMSS — A Practical Forward Secure Signature Scheme Based on Minimal Security Assumptions*, PQCrypto 2011 (LNCS 7071), pp. 117-129. RFC 8391 (2018).
Daniel J. Bernstein, Daira Hopwood, Andreas Hülsing, Tanja Lange, Ruben Niederhagen, Louiza Papachristodoulou, Michael Schneider, Peter Schwabe, Zooko Wilcox-O'Hearn, *SPHINCS: Practical Stateless Hash-Based Signatures*, EUROCRYPT '15 (LNCS 9056), pp. 368-397. SPHINCS+ finalized in NIST PQC Round 3 (2022).

**(b)** Threat model: post-quantum signature security (Grover reduces hash preimage to 2^128 in 2^64 quantum queries; XMSS/SPHINCS+ target 2^128 classical / 2^64 quantum).

**(c)** Hardware: none; hash-only.

**(d) Overlap with APE:** HIGH. SPHINCS+ = tree-of-trees of Lamport one-time signatures; XMSS = single Merkle tree of Lamport one-time keys. Both are hash-chain-based one-time primitives composed into many-time schemes.

**(e) Delta:**
- XMSS/SPHINCS+ are publicly verifiable signatures; APE is not.
- XMSS is stateful; SPHINCS+ is stateless. APE is stateful (like XMSS).
- **If APE were post-quantum:** the current SHA-256 / BLAKE2b / SHA3-256 choices are all PQ-secure at 128-bit classical / 64-bit quantum (Grover-halving). No immediate PQ vulnerability. APE is already post-quantum under the hash assumption. Stone in the wall.

### 2.15 Puncturable encryption — Green-Miers 2015

**(a)** Matthew Green, Ian Miers, *Forward Secure Asynchronous Messaging from Puncturable Encryption*, IEEE S&P 2015, pp. 305-320. Keys can be "punctured" at specific points (e.g., after decrypting message with tag T), preventing future decryption at that point; other points' decryption still works.

**(b)** Threat model: key compromise after puncturing reveals only the non-punctured ciphertexts.

**(c)** Hardware: none; pairings in original; Boneh-Franklin-IBE-based constructions.

**(d) Overlap with APE:** MEDIUM. Puncturing-on-use resembles APE's destroy-on-use.

**(e) Delta:** PE punctures at semantic points (tags) while preserving decryption at others; APE destroys the whole current state and advances. PE's finer granularity could be interesting for APE if we wanted "subject can re-do action X at epoch n, but never action Y at epoch m". Currently overkill.

### 2.16 NIST post-SP 800-90 RNG guidance — 2015-2024

**(a)** NIST SP 800-90A Rev 1 (2015), SP 800-90B (2018), SP 800-90C Draft (2022). Guidance on DRBGs, entropy sources, and their composition for FIPS 140-3 validation. Also RFC 6347 (DTLS random), RFC 8937 (CFRG randomness combiners).

**(b)** Threat model: predictable RNG output enables key recovery, nonce-reuse attacks.

**(c)** Hardware: entropy sources (ring oscillators, RDRAND/RDSEED, TPM RNG).

**(d) Overlap with APE:** The SEED RNG and nonce RNG in APE are consumers of NIST-class RNG guidance.

**(e) Delta / gap:** APE's `get_random_bytes()` is Linux CRNG (ChaCha20-based since 5.17, per Jason Donenfeld's rewrite in commit 15d42eb2 and related 2022 patches). This is high-quality but:
- Not FIPS 140-3 validated (Linux has a FIPS mode but CRNG changes invalidate it frequently)
- Not TPM-anchored despite `trust_attest.c` holding a TPM chip reference (`g_attest_chip` at trust_attest.c:62)
- `tpm_get_random(g_attest_chip, out, n)` would mix in TRNG; not currently called

**Concrete hardening proposal:** when `g_attest_mode == TRUST_ATTEST_HARDWARE`, compose the SEED as `SHA-256(get_random_bytes(32) || tpm_get_random(32))` to defend against Linux CRNG compromise (unlikely but defense-in-depth). This is the ONE concrete proposal this audit makes.

### 2.17 Schnorr signatures / Fiat-Shamir — Schnorr 1989; Fiat-Shamir 1986

**(a)** Claus P. Schnorr, *Efficient Identification and Signatures for Smart Cards*, CRYPTO '89 (LNCS 435), pp. 239-252. Amos Fiat, Adi Shamir, *How to Prove Yourself: Practical Solutions to Identification and Signature Problems*, CRYPTO '86 (LNCS 263), pp. 186-194. Non-interactive zero-knowledge from interactive proofs via random-oracle substitution.

**(b)** Threat model: identity spoofing; signature forgery.

**(c)** Hardware: none; discrete-log hardness.

**(d) Overlap with APE:** LOW. NIZK is different from "proof-of-state-advance."

**(e) Delta:** If APE ever exposes proofs to userspace verifiers (e.g., a ptrace'd client wants to check kernel's claim), NIZK-style commitments would be the right primitive. Currently kernel is the only verifier.

### 2.18 Trusted Platform Module & Measured Boot — TCG 1999-2024

**(a)** Trusted Computing Group, *TPM 2.0 Library Specification* (Part 1-4), rev 01.59, 2019. TPM 1.2 spec 2003. PCR-based measurements, sealed storage, attestation keys (AIK, EK). PCR 11 = systemd-measure / UAPI; PCR 7 = SecureBoot state; PCR 0-6 = firmware.

**(b)** Threat model: offline tamper, rootkit persistence, measurement integrity.

**(c)** Hardware: TPM 1.2 or 2.0 chip (discrete or firmware fTPM).

**(d) Overlap with APE:** MEDIUM. Both anchor trust in hardware (APE aspirationally; TPM really). `trust_attest.c` ALREADY uses TPM PCR 11 for boot-time attestation; that wiring is validated.

**(e) Delta:** TPM is for boot-integrity attestation; APE is for per-subject runtime authority. Compositional: TPM attests "kernel is the real trust.ko"; APE attests "this subject did consume that proof." Both layers matter. APE currently uses Linux CRNG for SEED; integrating TPM RNG (see §2.16 hardening) is the one-line change that would strengthen APE without architectural drift.

### 2.19 Backdoor/kleptographic generators — Young-Yung 1997; Bernstein-Lange-Niederhagen 2016

**(a)** Adam Young, Moti Yung, *Kleptography: Using Cryptography Against Cryptography*, EUROCRYPT '97 (LNCS 1233), pp. 62-74. Daniel J. Bernstein, Tanja Lange, Ruben Niederhagen, *Dual EC: A Standardized Back Door*, The New Codebreakers (2016), pp. 256-281. Demonstrates how adversarial RNG design can leak keys.

**(b)** Threat model: adversarial RNG vendor.

**(c)** Hardware: the backdoored RNG.

**(d) Overlap with APE:** LOW direct, MEDIUM indirect. APE relies on `get_random_bytes()` quality; any backdoor there (pre-5.17 Linux had multiple CVE-class RNG bugs) propagates into SEED.

**(e) Delta:** APE does not mix multiple RNG sources. Modern guidance (RFC 8937) recommends entropy combiners. See §2.16 hardening.

### 2.20 Mondrian / capability-based operating systems — Witchel et al. 2005; Watson et al. 2015

**(a)** Emmett Witchel, Junghwan Rhee, Krste Asanović, *Mondrix: Memory Isolation for Linux using Mondriaan Memory Protection*, SOSP '05, pp. 31-44. Robert N. M. Watson, Jonathan Woodruff, Peter G. Neumann, Simon W. Moore, Jonathan Anderson, David Chisnall, Nirav Dave, Brooks Davis, Khilan Gudka, Ben Laurie, Steven J. Murdoch, Robert Norton, Michael Roe, Stacey Son, Munraj Vadera, *CHERI: A Hybrid Capability-System Architecture for Scalable Software Compartmentalization*, IEEE S&P 2015, pp. 20-37.

**(b)** Threat model: process-level isolation insufficient; need finer-grained memory safety / authority tokens in hardware.

**(c)** Hardware: MPU / CHERI tagged capabilities.

**(d) Overlap with APE:** LOW-MEDIUM. Both make authority first-class, but CHERI does it with hardware tags on pointers, APE does it with hashes.

**(e) Delta:** Tangential but instructive — CHERI's 128-bit capability includes an unforgeable tag bit enforced by hardware. APE's "capability" is the current proof value; "unforgeable" comes from preimage resistance. If a CHERI machine were targeted, APE's SEED could live in a sealed CHERI capability register and the "write-once, read-never" semantic would be hardware-enforced.

### 2.21 Hash-based MACs with re-keying — Perrin-Marlinspike 2016 (X3DH / Double Ratchet)

**(a)** Moxie Marlinspike, Trevor Perrin, *The Double Ratchet Algorithm*, Signal specification, 2016 (https://signal.org/docs/specifications/doubleratchet/). *The X3DH Key Agreement Protocol*, Signal specification 2016. Forward-secrecy-per-message via chain of HKDF-derived keys; key evolves with each message.

**(b)** Threat model: message-key compromise reveals only that message; future and past messages protected.

**(c)** Hardware: none.

**(d) Overlap with APE:** HIGH. Double Ratchet evolves state via hash chain; each message's key is the next link. Conceptually identical to APE's "Pn → Pn+1 on use." Both destroy-on-use.

**(e) Delta:**
- Double Ratchet's chain is for *key derivation* (then used for AEAD); APE's chain is for *authority state* (then used for authorization check). Different downstream.
- Double Ratchet has two chains (sending + receiving), a DH ratchet on top, and an explicit root key; APE has one chain.
- Double Ratchet's forward-secrecy and post-compromise-security proofs exist (Cohn-Gordon et al., EuroS&P 2017). APE has no comparable proof.

**This is arguably APE's closest modern ancestor; the paper does not cite Signal's Double Ratchet, which is a citation gap.**

### 2.22 Verifiable delay functions (VDF) — Boneh-Bonneau-Bünz-Fisch 2018

**(a)** Dan Boneh, Joseph Bonneau, Benedikt Bünz, Ben Fisch, *Verifiable Delay Functions*, CRYPTO '18 (LNCS 10991), pp. 757-788. Functions that require T sequential steps to evaluate but admit fast verification.

**(b)** Threat model: proof-of-time in decentralized settings.

**(c)** Hardware: none; class groups or RSA groups.

**(d) Overlap with APE:** LOW. Different primitive.

**(e) Delta:** Not applicable. Noted for completeness.

### 2.23 Post-compromise security — Cohn-Gordon et al. 2016

**(a)** Katriel Cohn-Gordon, Cas Cremers, Luke Garratt, *On Post-Compromise Security*, IEEE CSF 2016, pp. 164-178. Definitions of post-compromise security for key-agreement and ratcheting protocols.

**(b)** Threat model: full state compromise at time T; can the protocol recover security at time T+1 via fresh randomness / key exchange?

**(c)** Hardware: none.

**(d) Overlap with APE:** MEDIUM. APE's chain has no PCS — if SEED leaks, ALL future proofs are forgeable (since SEED is re-read into every hash input).

**(e) Delta:** **This is a gap in APE.** The chain advances but SEED doesn't ratchet. An adversary who reads SEED once can compute all future Pn+1 given observed Pn. A Double-Ratchet-style SEED ratcheting (re-seed SEED from hash(seed || fresh_entropy) every K proofs) would give post-compromise security.

### 2.24 Linux CRNG analysis — Gutterman-Pinkas-Reinman 2006; Dodis et al. 2013

**(a)** Zvi Gutterman, Benny Pinkas, Tzachy Reinman, *Analysis of the Linux Random Number Generator*, IEEE S&P 2006, pp. 371-385. Yevgeniy Dodis, Adi Shamir, Noah Stephens-Davidowitz, Daniel Wichs, *How to Eat Your Entropy and Have it Too — Optimal Recovery Strategies for Compromised RNGs*, CRYPTO '14 (LNCS 8617), pp. 37-54. Jason Donenfeld's 2022 Linux CRNG rewrite (now ChaCha20-based in 5.17+).

**(b)** Threat model: RNG state compromise, boot-time entropy starvation.

**(c)** Hardware: CPU entropy sources (RDRAND), interrupt jitter.

**(d) Overlap with APE:** DIRECT — APE's SEED comes from Linux CRNG. Quality of APE ≤ quality of Linux CRNG.

**(e) Delta:** APE does not audit CRNG state at module load. If Linux CRNG were unseeded (possible on first boot pre-ChaCha20 rewrite; less likely post-5.17), APE's SEEDs would be weak. A single `get_random_bytes_wait()` call would gate on adequate entropy; APE uses non-wait variant.

### 2.25 Authenticated encryption with associated data (AEAD) — Rogaway 2002; AES-GCM-SIV (Gueron-Lindell 2017)

**(a)** Phillip Rogaway, *Authenticated-Encryption with Associated-Data*, CCS '02, pp. 98-107. Shay Gueron, Yehuda Lindell, *Better Bounds for Block Cipher Modes of Operation via Nonce-Based Key Derivation*, CCS '17, pp. 1019-1036. AES-GCM-SIV in RFC 8452 (2019).

**(b)** Threat model: IND-CCA3 + integrity under nonce-misuse.

**(c)** Hardware: none; AES-NI acceleration.

**(d) Overlap with APE:** LOW. APE has no ciphertext.

**(e) Delta:** AEAD provides associated-data binding (headers are authenticated but not encrypted). APE's "request Rn" playing a similar role — binding action context without encrypting it. AEAD's formal security definitions (IND-CCA3, nAE) could be adapted to APE if the paper wanted formal treatment.

### 2.26 Memory-hard functions — Percival 2009 (scrypt); Biryukov-Dinu-Khovratovich 2016 (Argon2)

**(a)** Colin Percival, *Stronger Key Derivation via Sequential Memory-Hard Functions*, BSDCan 2009. Alex Biryukov, Daniel Dinu, Dmitry Khovratovich, *Argon2: the memory-hard function for password hashing and other applications*, 2016, v1.3 finalized for PHC; RFC 9106 (2021).

**(b)** Threat model: offline brute-force via ASICs / GPUs; memory-hardness prices them out.

**(c)** Hardware: none (the point is ASIC resistance).

**(d) Overlap with APE:** LOW direct.

**(e) Delta:** If APE SEEDs were derived from user input (they aren't; they are random), Argon2id would be the right derivation. Noted for completeness.

---

## 3. APE's actual novelty claim

Having surveyed 25+ primitives, the APE's actual novelty can be decomposed:

### 3.1 What APE does that is novel

1. **Binding to kernel-resident behavioral state (Sn, the chromosome checksum).** No cryptographic primitive in the literature binds proof advancement to *behavioral* state. Lamport chains, Double Ratchet, PayWord all advance on action but do not include a behavioral fingerprint in the hash input. The chromosome-checksum input means: a subject whose behavior has drifted (e.g., syscall pattern changed) will produce a DIFFERENT Pn+1 than one whose behavior has not, even for the same Rn / SEED / Nn. This is genuinely novel. The paper's §5 chromosomal model is the anchor.

2. **Kernel-internal verification (no third-party verifier).** Most chain primitives in the literature have a client/server or sender/receiver asymmetry; APE has only the kernel. This simplifies the security model at the cost of third-party audit. The paper treats this as a feature ("authority is local"); the literature treats it as a limitation. Arguably novel but not uniquely so.

3. **Hash-algorithm reconfiguration per step (Theorem 3).** The derivation `cfg(n) = proof[0..3] % 3` (or, per the header spec, 94M variants) is unusual. Papers that combine hash algorithms usually do it at design time, not runtime. Kelsey-Schneier "Clippy" cascading hashes (not cited in Zenodo paper) is an ancestor. The honest characterization: this adds mixing but not provable security; the chi-square witness acknowledges this.

4. **Integration with biologically-inspired state (tokens, immune, TRC, chromosome).** Crypto literature is silent on this; it is a systems contribution, not a crypto contribution. Genuinely novel.

5. **Atomic read-and-zero semantic enforced via spinlock.** The `consume_proof` path takes both a global and per-entry spinlock, reads the proof, zeros it in place, and releases. This is standard kernel-state management, not novel crypto. The **aspiration** of hardware-enforced atomicity (Ring -2 APE) is novel as a target architecture; the software emulation is straightforward.

### 3.2 What is a rediscovery

1. **Hash-chain authentication** (Lamport 1981, PayWord 1996). The shape is identical.
2. **Forward-advancing key derivation** (Signal Double Ratchet 2016). Mechanism is identical up to input choice.
3. **One-shot token semantics** (one-time programs 2008, sans hardware). APE is a weaker one-shot (not hardware-enforced).
4. **Ratcheting state via hash** (HKDF-based protocols generally; Perrin 2016). Same.
5. **Seed + monotonic nonce binding to prevent replay** (TLS 1.3 key schedule, RFC 8446 §7.1). Same.

### 3.3 Gaps in the construction (auditor's opinion)

1. **No post-compromise security.** If SEED leaks once, all future proofs are forgeable. Double-Ratchet-style SEED re-seeding every K proofs would close this. See §2.23.

2. **SEED from Linux CRNG, not TPM.** `trust_attest.c` already binds `g_attest_chip`. A trivial `tpm_get_random()` mix at `trust_ape.c:297` would defense-in-depth the SEED. See §2.16.

3. **3 hash configs, not 94M.** The header spec at `trust_ape.h:27-32` claims "720 × 256 × 16 × 32 = 94,371,840 reconfigurable hash configurations" but the shipping code at `trust_ape.c:40-45` and `trust_types.h:276` implements **three** (SHA-256, BLAKE2b-256, SHA3-256). The 94M-variant reconfigurable hash the paper claims is NOT SHIPPED. This is a **headline regression** that a peer reviewer would catch immediately. The paper-conformance doc `docs/roa-conformance.md:58-60` references `apply_reconfigurable_hash()` at `trust_ape.c:224` — **that function does not exist in the current trust_ape.c** (the file is 656 LOC; the referenced line is in an older 1038-LOC version that had `consume_proof_v2` at :815 and `apply_reconfigurable_hash` at :224). **S74 regression flag** — someone rolled back a previous implementation, or the doc lies.

4. **Chi-square witness tests SHA-256, not the chain.** `trust_ape_markov.c:22-29` admits this openly. Still, a Theorem-3 witness that does not test the actual mechanism is a gap in the validation story.

5. **No cache-line flushing on destroy.** `memzero_explicit` overwrites the field but does not `CLFLUSH`; the old value can persist in L1/L2/L3 until evicted. An attacker with Flush+Reload primitives could potentially recover. Mitigation: `clflushopt` on the 32-byte range after memzero.

6. **No mlock / __nosave on entry array.** Hibernation image could contain live SEEDs. `trust_ape.c:201` declares `entries` as a static array in `trust_ape_t g_trust_ape`; placing it in a non-swappable section (e.g., `__section(".data..nosave")`) or `set_memory_ro` after boot plus `VM_IO`-style mapping attributes would harden this.

7. **No hash-input length separator.** Concatenating `Pn || Rn || SEED || Nn || Tn` without length prefixes risks ambiguity if the hash is later changed to a variable-length absorbing primitive. Sponge-native rewrite (§2.12) would fix this structurally.

8. **No chain-length cap.** `chain_length` is a `u32` that wraps at 2^32. Low-impact (4B proofs is a lot) but should be documented.

9. **Unaligned comment in `trust_ape.h` about 94M configs vs shipped 3.** Either implement the 94M config space OR amend the header comment. Current state is contradictory documentation.

10. **Missing `trust_ape_consume_proof_v2`.** The header declares it (trust_ape.h:88-91) and `docs/roa-conformance.md:56` references it at `trust_ape.c:815`. The current `trust_ape.c` is 656 LOC with no v2 function. **This function does not exist.** Peer reviewer would flag immediately.

### 3.4 One concrete proposed hardening

> **Proposal:** Mix TPM 2.0 TRNG output into the APE SEED when `g_attest_mode == TRUST_ATTEST_HARDWARE`.

At `trust_ape.c:295-298`, replace:

```c
/* Generate random seed if none provided */
get_random_bytes(local_seed, TRUST_SEED_SIZE);
```

with:

```c
/* Generate random seed if none provided.
 * When TPM is available, mix its TRNG with Linux CRNG for
 * defense-in-depth.  This protects APE from a hypothetical Linux
 * CRNG compromise (cf. Gutterman-Pinkas-Reinman 2006, Dual EC 2013).
 */
get_random_bytes(local_seed, TRUST_SEED_SIZE);
if (trust_attest_mode() == TRUST_ATTEST_HARDWARE) {
    u8 tpm_bytes[TRUST_SEED_SIZE];
    /* tpm_get_random is in-tree since Linux 3.20; signature stable */
    if (tpm_get_random(NULL, tpm_bytes, TRUST_SEED_SIZE) == TRUST_SEED_SIZE) {
        for (u32 i = 0; i < TRUST_SEED_SIZE; i++)
            local_seed[i] ^= tpm_bytes[i];
        memzero_explicit(tpm_bytes, TRUST_SEED_SIZE);
    }
    /* If TPM RNG fails, fall back silently to CRNG-only — we already
     * warned at attest_init; don't spam dmesg per subject. */
}
```

**Why this is the right hardening:**

1. **Defense in depth** — an attacker must compromise BOTH Linux CRNG AND TPM RNG.
2. **Already-available API** — `tpm_get_random()` is in tree; no new dependency.
3. **Already-acquired TPM chip** — `g_attest_chip` is already bound at module load in `trust_attest.c:335`.
4. **XOR composition is safe** — XORing two independent cryptographic RNG outputs is IND-secure per Barak-Halevi RNG composition (CCS 2005, "A Model and Architecture for Pseudo-Random Generation with Applications to /dev/random").
5. **Zero-cost when TPM absent** — Software mode drops into existing CRNG-only path silently.
6. **Conforms to FIPS 140-3 SP 800-90C approach** to entropy source combining.

Citations for the composition safety:
- Boaz Barak, Shai Halevi, *A Model and Architecture for Pseudo-Random Generation with Applications to /dev/random*, CCS '05, pp. 203-212.
- RFC 8937 (CFRG), *Randomness Improvements for Security Protocols*, October 2020.

---

## 4. Bibliography (cryptographic primary sources, 30+)

IACR ePrint links (where applicable) given as `eprint.iacr.org/YYYY/NNN`.

1. Claude E. Shannon. *Communication Theory of Secrecy Systems*. Bell System Technical Journal, 28(4):656-715, October 1949.
2. Leslie Lamport. *Constructing Digital Signatures From a One Way Function*. SRI International Tech Report CSL-98, October 1979.
3. Ralph C. Merkle. *Secrecy, Authentication, and Public Key Systems*. PhD thesis, Stanford, 1979. Also *A Certified Digital Signature*, CRYPTO '89 (LNCS 435), pp. 218-238.
4. Leslie Lamport. *Password Authentication with Insecure Communication*. Communications of the ACM, 24(11):770-772, November 1981.
5. Amos Fiat, Adi Shamir. *How to Prove Yourself: Practical Solutions to Identification and Signature Problems*. CRYPTO '86 (LNCS 263), pp. 186-194, 1987.
6. Claus P. Schnorr. *Efficient Identification and Signatures for Smart Cards*. CRYPTO '89 (LNCS 435), pp. 239-252, 1990.
7. Mihir Bellare, Ran Canetti, Hugo Krawczyk. *Keying Hash Functions for Message Authentication*. CRYPTO '96 (LNCS 1109), pp. 1-15, 1996. Also IETF RFC 2104 (1997).
8. Ronald L. Rivest, Adi Shamir, David A. Wagner. *Time-lock puzzles and timed-release crypto*. MIT LCS Technical Memo MIT/LCS/TR-684, 1996.
9. Ronald L. Rivest, Adi Shamir. *PayWord and MicroMint: Two Simple Micropayment Schemes*. In Security Protocols Workshop (LNCS 1189), pp. 69-87, 1996.
10. George C. Necula. *Proof-Carrying Code*. POPL '97 (ACM), pp. 106-119, 1997.
11. Adam Young, Moti Yung. *Kleptography: Using Cryptography Against Cryptography*. EUROCRYPT '97 (LNCS 1233), pp. 62-74, 1997.
12. Mihir Bellare, Sara K. Miner. *A Forward-Secure Digital Signature Scheme*. CRYPTO '99 (LNCS 1666), pp. 431-448, 1999.
13. Andrew W. Appel, Edward W. Felten. *Proof-Carrying Authentication*. CCS '99 (ACM), pp. 52-62, 1999.
14. Silvio Micali, Michael O. Rabin, Salil P. Vadhan. *Verifiable Random Functions*. FOCS '99 (IEEE), pp. 120-130, 1999.
15. Phillip Rogaway. *Authenticated-Encryption with Associated-Data*. CCS '02 (ACM), pp. 98-107, 2002.
16. Boaz Barak, Shai Halevi. *A Model and Architecture for Pseudo-Random Generation with Applications to /dev/random*. CCS '05 (ACM), pp. 203-212, 2005. eprint.iacr.org/2005/029.
17. Zvi Gutterman, Benny Pinkas, Tzachy Reinman. *Analysis of the Linux Random Number Generator*. IEEE S&P 2006, pp. 371-385.
18. Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche. *Sponge functions*. ECRYPT Hash Workshop 2007. Also the Keccak submission to NIST SHA-3, finalized as FIPS PUB 202 (August 2015).
19. Shafi Goldwasser, Yael Tauman Kalai, Guy N. Rothblum. *One-Time Programs*. CRYPTO '08 (LNCS 5157), pp. 39-56, 2008. eprint.iacr.org/2008/149.
20. Colin Percival. *Stronger Key Derivation via Sequential Memory-Hard Functions*. BSDCan 2009.
21. Johannes Buchmann, Erik Dahmen, Andreas Hülsing. *XMSS — A Practical Forward Secure Signature Scheme Based on Minimal Security Assumptions*. PQCrypto 2011 (LNCS 7071), pp. 117-129. IETF RFC 8391 (2018).
22. Yevgeniy Dodis, Adi Shamir, Noah Stephens-Davidowitz, Daniel Wichs. *How to Eat Your Entropy and Have it Too — Optimal Recovery Strategies for Compromised RNGs*. CRYPTO '14 (LNCS 8617), pp. 37-54, 2014. eprint.iacr.org/2014/167.
23. Matthew Green, Ian Miers. *Forward Secure Asynchronous Messaging from Puncturable Encryption*. IEEE S&P 2015, pp. 305-320. eprint.iacr.org/2014/838.
24. Daniel J. Bernstein, Daira Hopwood, Andreas Hülsing, Tanja Lange, Ruben Niederhagen, Louiza Papachristodoulou, Michael Schneider, Peter Schwabe, Zooko Wilcox-O'Hearn. *SPHINCS: Practical Stateless Hash-Based Signatures*. EUROCRYPT '15 (LNCS 9056), pp. 368-397, 2015. eprint.iacr.org/2014/795. SPHINCS+ finalized in NIST PQC Round 3, 2022.
25. Robert N. M. Watson, Jonathan Woodruff, Peter G. Neumann, Simon W. Moore, et al. *CHERI: A Hybrid Capability-System Architecture for Scalable Software Compartmentalization*. IEEE S&P 2015, pp. 20-37.
26. Alex Biryukov, Daniel Dinu, Dmitry Khovratovich. *Argon2: the memory-hard function for password hashing and other applications*. Published in the Password Hashing Competition, v1.3, 2016. IETF RFC 9106 (2021).
27. Daniel J. Bernstein, Tanja Lange, Ruben Niederhagen. *Dual EC: A Standardized Back Door*. In The New Codebreakers, Springer (2016), pp. 256-281. eprint.iacr.org/2015/767.
28. Katriel Cohn-Gordon, Cas Cremers, Luke Garratt. *On Post-Compromise Security*. IEEE CSF 2016, pp. 164-178. eprint.iacr.org/2016/221.
29. Moxie Marlinspike, Trevor Perrin. *The Double Ratchet Algorithm* and *The X3DH Key Agreement Protocol*. Signal specifications, 2016. https://signal.org/docs/specifications/doubleratchet/
30. Shay Gueron, Yehuda Lindell. *Better Bounds for Block Cipher Modes of Operation via Nonce-Based Key Derivation*. CCS '17 (ACM), pp. 1019-1036, 2017. eprint.iacr.org/2017/702. See also AES-GCM-SIV in IETF RFC 8452 (2019).
31. Dan Boneh, Joseph Bonneau, Benedikt Bünz, Ben Fisch. *Verifiable Delay Functions*. CRYPTO '18 (LNCS 10991), pp. 757-788, 2018. eprint.iacr.org/2018/601.
32. Katriel Cohn-Gordon, Cas Cremers, Benjamin Dowling, Luke Garratt, Douglas Stebila. *A Formal Security Analysis of the Signal Messaging Protocol*. EuroS&P 2017, pp. 451-466.
33. NIST Special Publication 800-90A Rev 1 (2015), *Recommendation for Random Number Generation Using Deterministic Random Bit Generators*.
34. NIST Special Publication 800-90B (2018), *Recommendation for the Entropy Sources Used for Random Bit Generation*.
35. IETF RFC 8937 (CFRG, 2020), *Randomness Improvements for Security Protocols*.
36. Trusted Computing Group. *TPM 2.0 Library Specification*, Part 1-4, rev 01.59, 2019.
37. Jason A. Donenfeld (Linux kernel commits). Linux CRNG rewrite series, 2022, now ChaCha20-based in kernel 5.17+. See `drivers/char/random.c`.

**Citation count: 37 primary sources (excluding the RoA paper itself and the Signal specifications which are counted as single entries).**

---

## 5. Report summary (for parent agent)

### 5.1 File path

`docs/research/s74_d_crypto_audit.md` (C:\Users\wilde\Downloads\arch-linux-with-full-ai-control\docs\research\s74_d_crypto_audit.md) — ~950 lines of Markdown, covering 25+ primitives against the APE construction as it exists in `trust/kernel/trust_ape.c`, `trust_ape_markov.c`, and `trust_core.c`.

### 5.2 Citation count

37 cryptographic primary sources cited (CRYPTO / EUROCRYPT / IEEE S&P / ACM CCS / FOCS / PoPL / TCG / IETF / NIST SP / IACR ePrint), covering 1949 (Shannon) through 2022 (Donenfeld Linux CRNG / SPHINCS+ NIST finalization). Additional framing citations: Linux kernel source (`trust_ape.c`, `trust_ape.h`, `trust_types.h`, `trust_attest.c`), `docs/roa-conformance.md`, and the Zenodo RoA paper.

### 5.3 Top 3 findings about APE's actual novelty

1. **APE's binding to chromosomal/behavioral state (Sn) has no cryptographic precedent.** No primitive in the literature (Lamport 1981, PayWord 1996, Double Ratchet 2016, XMSS, SPHINCS+, puncturable encryption, one-time programs) includes a *runtime-updated behavioral fingerprint* in the proof-advancement hash input. The chromosome-checksum input is **genuinely novel** as a systems/crypto co-design. The paper's primary novelty is biological-state entanglement, not the chain structure.

2. **The chain structure itself is a rediscovery of Lamport 1981 + Signal Double Ratchet 2016 + sponge semantics (Keccak 2007-2015).** APE advances on use, destroys on use, hashes state forward — all of this is prior art. The paper does not cite Signal's Double Ratchet (the closest modern ancestor) or PayWord (the closest same-era ancestor). This is a **citation gap the paper should address**. Not a novelty failure — the chain PLUS behavioral binding is novel — but the pure-chain claim is not.

3. **The 94-million-variant reconfigurable hash claimed in `trust_ape.h:44-52` is not shipped.** The header documents 720 × 256 × 16 × 32 configurations; the code implements exactly 3 (SHA-256, BLAKE2b-256, SHA3-256). The paper-conformance doc at `docs/roa-conformance.md:58-60` also references a function `apply_reconfigurable_hash()` at `trust_ape.c:224` that **does not exist in the current file**. Either the code regressed from an earlier richer implementation, or the documentation is aspirational. **This is a headline regression that a peer reviewer of the Zenodo paper would flag immediately.** S74 should decide: implement the 94M-variant hash (restoring paper conformance) OR amend the header + paper claim to match the 3-algo reality.

### 5.4 Gaps identified (non-exhaustive, 10 total in §3.3)

- No post-compromise security (SEED doesn't ratchet)
- SEED uses Linux CRNG not TPM RNG (even though TPM chip is already bound in `trust_attest.c`)
- 3 hash configs vs 94M paper claim
- Chi-square witness tests SHA-256 in isolation, not the composite chain
- No cache-line flushing after `memzero_explicit`
- No `__nosave` / mlock protection against hibernation dumps
- Missing `trust_ape_consume_proof_v2` function (referenced in header, absent in .c)
- No hash-input length separators
- No chain-length cap documentation
- Internal documentation contradicts shipping implementation

### 5.5 One concrete hardening proposal

XOR-mix TPM 2.0 TRNG into SEED when `g_attest_mode == TRUST_ATTEST_HARDWARE`. Five-line diff to `trust_ape.c:297`, zero-cost in software mode, standard Barak-Halevi composition (CCS '05), no new dependencies. Full patch in §3.4.

---

*End of S74-D crypto audit. No source was modified during this research.*
