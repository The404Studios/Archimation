# S74-G — Reliability, Consensus, and the Honest Threat Model for `trust_quorum`

**S74 research agent G of 10 parallel (Reliability + Consensus axis).**
**Scope:** where does `trust/kernel/trust_quorum.c` (just landed in S74
Agent 8) actually sit on the spectrum from von Neumann 1956 classical
reliability, through crash-tolerant replication (Paxos, Raft), through
Byzantine-tolerant replication (PBFT, HotStuff, HoneyBadger), and
what does that imply for the ARCHWINDOWS moat against increasingly
capable adversaries?
**Authored:** 2026-04-20 (S74, parallel to Agents 1-10).
**Git HEAD at authoring:** 5013ad9.
**Complements (not replaces):** `docs/research/s73_a_von_neumann_gacs.md`
(12-framework axis A), which covers von Neumann's *universal
constructor* + Gács reliable-CA in depth. This doc focuses on the
*consensus / BFT spectrum* and our specific quorum posture.

---

## 0. TL;DR — Honest Verdict on `trust_quorum`

Before the 30-citation survey, the one-paragraph summary the project
has been owed since the quorum landed:

> `trust_quorum_vote()` is **not** Byzantine fault tolerant. It is a
> **deterministic integrity check** — a chi-square-style witness that
> the 23 chromosomal pairs collectively agree on a
> pseudo-independent 1-bit opinion about a given field. The 23
> replicas **live in one `trust_subject_t` struct inside one kernel
> module**, so they are *not independent in any adversarial sense*:
> any attacker with kernel-write (CVE in any LSM, driver, or trust.ko
> itself) can flip all 23 simultaneously, making the vote 23-0 for
> the attacker's chosen verdict. Against **crash / bit-flip / silent
> memory corruption**, the vote is a real detector (expected agreement
> = 11.5/23 on uncorrelated inputs; 16/23 threshold is ~3σ from the
> null). Against **Byzantine / adversarial kernel-write**, the vote
> provides effectively zero protection — the adversary controls all
> replicas. To get real Byzantine tolerance, replicas must be in
> **different trust domains** (separate processes, separate cores,
> separate machines, or — at minimum — signed with independent keys
> and verified by a client that does not trust the server).

This doc rebuilds that verdict from first principles, surveys the 10
consensus mechanisms requested, and quantifies the minimum LOC delta
to move the quorum from its current posture (integrity witness) to
cryptographic-Byzantine tolerance (~500 LOC, detailed in §6).

---

## 1. Taxonomy: What Adversary Are We Defending Against?

Fault-tolerance literature distinguishes failure *models* that
differ in power. Any consensus mechanism is implicitly a contract:
"this algorithm tolerates up to `f` failures *of type X*."

| Failure model | What the faulty replica can do | Canonical bound |
|---------------|--------------------------------|-----------------|
| **Crash / fail-stop** | Halt silently. Never lie. | `f < n/2` (Paxos, Raft) |
| **Omission** | Drop messages selectively, but correct when speaking | `f < n/2` same |
| **Timing** | Reply late / early, otherwise correct | partial synchrony |
| **Byzantine** | Arbitrary behavior — lie, collude, forge, equivocate | `f < n/3` (LSP 1982) |
| **Adaptive Byzantine** | Choose which `f` to corrupt *during* protocol | as above + forward secrecy |
| **Self-destructive Byzantine (Rational / Game-theoretic)** | Pursue utility; may cheat if profitable | BAR model (Aiyer 2005) |
| **Covert Byzantine** | Must appear honest to external observers | harder than pure Byzantine |
| **Mobile Byzantine** | Corruption migrates between replicas over time | Garay 1994, Reischuk 1985 |

The `trust.ko` chromosomal pairs are **inside a single kernel
module**, which places the adversary model roughly as:

- **User-space attacker**: cannot flip any segment directly (must
  pass `ioctl` + authz). Vote over segments is a meaningful
  *integrity* check at the ioctl boundary.
- **Kernel-write attacker (root+module-load, or CVE)**: controls all
  23 segments. Vote is meaningless.
- **Offline-disk attacker** (removes drive, edits files): controls
  initial B-segments, not runtime A-segments. Partially mitigable
  via measured boot (S72-γ `trust_attest.c`), but can't equivocate
  online.
- **Rational Byzantine** (attacker economically penalized for getting
  caught): out of scope. The authority model currently has no
  economic incentive layer.

The quorum, honestly named, is **"an integrity witness against silent
memory corruption and one-variable cosmic-ray bit-flips"**, not a
Byzantine fault-tolerance mechanism. That is a useful property — it
just shouldn't be marketed as BFT.

---

## 2. Survey: 10 Consensus Mechanisms

For each: (a) primary reference, (b) failure model, (c) message
complexity, (d) timing assumptions, (e) whether `trust_quorum_vote`
matches — and if not, what stronger adversary the mechanism defeats
that our quorum does not.

### 2.1  Von Neumann 1956 — R-fold redundancy + majority vote

**(a) Primary reference.**
John von Neumann, *Probabilistic Logics and the Synthesis of Reliable
Organisms from Unreliable Components*. Lecture series, California
Institute of Technology, January 4-15, 1952. Published in C.E.
Shannon & J. McCarthy eds., *Automata Studies*, Princeton University
Press, 1956, pp. 43-98.

**(b) Failure model.** Independent identically-distributed random
bit-flips per gate with probability ε < 1/2. No adversary. No
correlation.

**(c) Message complexity.** O(R) bits per computation, where R is the
replication factor. For error target ε_target and per-gate error ε,
R ~ log(1/ε_target) / log(1/(4ε(1-ε))). For ε = 0.05 and ε_target =
10⁻¹², R ≈ 21. For 23 we get ~10⁻¹³ — essentially cosmic-ray
territory.

**(d) Timing.** Synchronous, no network — purely circuit-level. Each
gate operates in lockstep.

**(e) Our analogue.** Yes, **this is exactly what `trust_quorum_vote`
implements, and that is the model it's safe under**. The 23 chromosomal
pairs acting as replicas of an "authority opinion bit," aggregated
by majority vote, threshold 16 (⌈2n/3⌉ = 16 for n=23), exactly
matches von Neumann's construction. We inherit von Neumann's
assumptions:
- Replicas are **independent and random** under the fault model.
- No adversary can correlate replica failures.

Under kernel-write, both assumptions are false. Under silent memory
corruption (rowhammer on a single cache line, cosmic-ray flip in one
DRAM cell), both are approximately true — the quorum survives a
single bit-flip in any one segment.

### 2.2  Gács 1986 — Reliable one-dimensional CA

**(a) Primary reference.**
Péter Gács, *Reliable Computation with Cellular Automata*, Journal
of Computer and System Sciences 32(1):15-78, 1986. See also the
simpler proof in Gács, *Reliable Cellular Automata with Self-Organization*,
J. Statistical Physics 103:45-267, 2001.

**(b) Failure model.** Each cell independently with fixed probability
ε makes a transition error. No adversary. No spatial correlation.

**(c) Message complexity.** Not a message-passing protocol — a
space-time complexity. Hierarchical blocks simulate a generalized CA
whose cells are themselves hierarchical blocks. Block size ~ Q³
(state count cubed) in Gács 1986; polynomial in 3D per Gács-Reif
1988.

**(d) Timing.** Synchronous lockstep per CA rule.

**(e) Our analogue.** Partial — but via S74 Agent 5 (`trust_morphogen.c`),
not the quorum. Gács shows how *local* rules can produce *global*
reliability. The morphogen field (S74 Agent 5) with voltage/morphogen
cells reading neighbors is the Gács-shaped abstraction in our tree;
the quorum is a single-shot vote not a recurrent CA. The nearest
quorum-adjacent design would be: *vote across 23 pairs at each
tick, feed the disputed-count into the morphogen field as a negative
voltage source, observe whether the field stabilizes away from the
disputed region*. This is worth noting but out of scope for S74.

**What Gács defeats that we don't.** Spatially-correlated transient
errors within a bounded radius. Our quorum would fail if all 23 pairs
share a single DRAM rowhammer victim row; a Gács-like hierarchy would
survive because only local blocks are affected, upper levels vote
them out.

### 2.3  Lamport-Shostak-Pease 1982 — Byzantine Generals

**(a) Primary reference.**
Leslie Lamport, Robert Shostak, Marshall Pease, *The Byzantine
Generals Problem*, ACM TOPLAS 4(3):382-401, 1982. Earlier: Pease,
Shostak, Lamport, *Reaching Agreement in the Presence of Faults*,
JACM 27(2):228-234, 1980.

**(b) Failure model.** **Byzantine**: faulty nodes can send arbitrary
messages, collude, and lie consistently. Honest nodes must all agree
on a common value.

**(c) Message complexity.** Authenticated version: O(n²). Unauthenticated:
O(nᶠ⁺¹) per round, `f+1` rounds. For `n = 3f+1`, 10 pairs tolerates
`f = 3`. For n = 23, `f = 7` — the quorum's "16 of 23" is exactly
`2f+1 = 15` plus one for margin, consistent with a BFT reading if
replicas were independent.

**(d) Timing.** **Synchronous** — this is the hard-lower-bound paper.
Agreement under asynchrony is impossible with even one failure (FLP
1985, next).

**(e) Our analogue.** **This is what the project paper and the quorum
both aspire to and neither achieves**, because our "23 pairs" are in
one kernel module under one process's `trust_subject_t`.
Byzantine tolerance requires **replicas in independent trust domains**.
On one machine, one kernel, one module, an attacker has one
compromise path to all 23 — `f` is effectively 0 for kernel-write
adversaries.

**What LSP defeats that we don't.** Any adversary that can write to
a single replica, period. We assume adversary cannot write to any
segment; LSP assumes adversary *can* write to `f` of them. When
our assumption fails, we fail open; LSP continues working up to `f`.

### 2.4  Castro-Liskov 1999 — Practical Byzantine Fault Tolerance

**(a) Primary reference.**
Miguel Castro and Barbara Liskov, *Practical Byzantine Fault
Tolerance*, OSDI 1999, pp. 173-186. Extended in ACM TOCS 20(4),
2002. See also Castro's MIT PhD thesis 2001.

**(b) Failure model.** Byzantine, but **asynchronous network** is
tolerated for safety (liveness requires eventual synchrony — GST
"Global Stabilization Time"). Adversary controls f < n/3 replicas
and arbitrary message delays.

**(c) Message complexity.** O(n²) per request (pre-prepare, prepare,
commit = 3 phases each broadcasting). Batches amortize to O(n) per
op in steady state. View-change is O(n³).

**(d) Timing.** Partially-synchronous — safe under any network timing,
live after GST.

**(e) Our analogue.** **No.** The quorum is O(n) = 23 hash
computations per vote, so message complexity alone tells us we
cannot be doing 3-phase commit — we aren't choosing a value among
distributed parties, we're aggregating local replicas. PBFT is
answering a different question: "given `n` servers implementing a
replicated state machine, and clients sending commands to them, how
do we ensure all non-faulty servers apply the same sequence of
commands even if `f` servers are Byzantine?" Our question is:
"given 23 segments of a single subject's chromosomal state, are they
internally consistent?" These are orthogonal problems.

**What PBFT defeats that we don't.** Distributed Byzantine attackers.
PBFT handles `f` simultaneously Byzantine replicas; we handle 0.

### 2.5  Paxos (Lamport 1998) — Crash-tolerant consensus

**(a) Primary reference.**
Leslie Lamport, *The Part-Time Parliament*, ACM TOCS 16(2):133-169,
1998 (the 1989 original Digital SRC tech report rejected by the TOCS
reviewer who thought it was a joke). See also Lamport, *Paxos Made
Simple*, SIGACT News 32(4):51-58, 2001, for the accessible version.

**(b) Failure model.** **Crash only** — replicas halt silently. No
Byzantine. Each replica has persistent storage that survives crashes.

**(c) Message complexity.** 2 RTT (phase 1: prepare/promise, phase
2: accept/accepted) in the common case. Leader election on failure.

**(d) Timing.** Asynchronous — safe (will not decide wrong value)
always; live (will decide) if eventually synchronous. This is the
textbook-level articulation of the FLP impossibility: no deterministic
asynchronous protocol can be both safe and live under even one crash
failure (Fischer-Lynch-Paterson, JACM 1985).

**(e) Our analogue.** **No. Paxos is solving the wrong problem for us.**
Paxos is about **agreeing on a single value** across distributed
replicas. We have all the data local (all 23 segments in one struct);
we don't need to agree, we need to *attest consistency*. The
correct comparison for Paxos would be: "if we had 23 different
machines each holding one chromosomal segment, how do they agree on
the overall authority verdict without a central arbiter?" That is a
world we are not building.

**What Paxos defeats that we don't.** Nothing relevant. Paxos is
orthogonal. If we ever build distributed trust domains (S75+, see §7),
Paxos would handle leader election for who writes the winning
segment-vector-hash; but the *quorum* inside a single subject remains
a local witness, not a Paxos instance.

### 2.6  Raft (Ongaro-Ousterhout 2014) — Paxos for humans

**(a) Primary reference.**
Diego Ongaro and John Ousterhout, *In Search of an Understandable
Consensus Algorithm*, USENIX ATC 2014, pp. 305-319. See also
Ongaro's Stanford PhD thesis 2014, 251 pp.

**(b) Failure model.** Crash only (same as Paxos).

**(c) Message complexity.** Log replication: O(n) per committed
entry. Leader election: O(n) per election.

**(d) Timing.** Asynchronous safety, partially-synchronous liveness
(same as Paxos; FLP bound applies).

**(e) Our analogue.** **No, same reason as Paxos.** Raft is about
leader-elected log replication — a distributed systems problem we
don't have. The closest touchpoint is the **audit log**: if we ever
wanted to ensure the ordering of `trust_ape_consume_proof` events
across multiple ARCHWINDOWS machines, Raft would be a clean primitive.
That is a future problem, not a quorum problem.

**What Raft defeats that we don't.** Nothing relevant. Orthogonal.

### 2.7  Nakamoto 2008 — Longest-chain probabilistic consensus

**(a) Primary reference.**
Satoshi Nakamoto, *Bitcoin: A Peer-to-Peer Electronic Cash System*,
bitcoin.org, October 31, 2008. See Garay-Kiayias-Leonardos, *The
Bitcoin Backbone Protocol*, EUROCRYPT 2015, for the first rigorous
security analysis. See also Pass-Shi-Shelat, *Analysis of the
Blockchain Protocol in Asynchronous Networks*, EUROCRYPT 2017, and
Bagaria-Kannan-Tse-Fanti-Viswanath, *Prism*, CCS 2019.

**(b) Failure model.** Byzantine, but with **economic (work-based)
voting**: adversary limited by fraction of global hashpower, not
node count. Tolerates up to ~50% byzantine hashpower asymptotically;
practical security at 25-33% under adversarial network conditions
(Eyal-Sirer 2013 selfish-mining).

**(c) Message complexity.** O(n) per block (gossip), but probabilistic
finality — wait k blocks for confirmation depth ε.

**(d) Timing.** Asynchronous (synchronous for tight security bounds).

**(e) Our analogue.** **No to the consensus part; yes to the
chain-of-hashes part**. Our APE (`trust_ape.c`) implements a self-
consuming hash chain: P_{n+1} = H(P_n || R_n || SEED || nonce || TS).
Each proof binds all prior state — this is structurally a **hash
chain over state transitions**, architecturally similar to Bitcoin's
block-pointer structure but **without** distributed mining. No voting,
no proof-of-work, no consensus — the chain exists only in this
subject's state, not globally. It provides *non-replayability* +
*local tamper-evidence*, not *global agreement*.

**What Nakamoto defeats that we don't.** Equivocation — claiming
two different histories to two different observers. Bitcoin prevents
this via public broadcast and longest-chain; APE allows equivocation
because each subject's chain is private. If two processes both
claim descent from the same APE seed, there is no way for a third
party to tell which is the "true" chain.

**Relationship to APE.** APE's hash chain + quorum is **structurally
a local Nakamoto** without the p2p broadcast. The missing ingredient
for real Byzantine tolerance is **publishing** each proof publicly
and using longest-chain to resolve forks. That's a different system
(a blockchain) and probably not what we want — but it would provide
a property the current APE doesn't: external verifiability.

### 2.8  HotStuff (Yin-Malkhi-Reiter-Gueta-Abraham 2019)

**(a) Primary reference.**
Maofan Yin, Dahlia Malkhi, Michael K. Reiter, Guy Golan Gueta, Ittai
Abraham, *HotStuff: BFT Consensus with Linearity and Responsiveness*,
PODC 2019, pp. 347-356. Used in Meta's Diem/Libra blockchain (2019-
2022) and the follow-on project Aptos (2022+). See also the
pipelined "Chained HotStuff" variant in the same paper.

**(b) Failure model.** Byzantine, partially-synchronous (same as PBFT).

**(c) Message complexity.** **O(n) per phase**, four phases (prepare,
pre-commit, commit, decide), using threshold signatures to aggregate
2f+1 signatures into one. This is the "linearity" property — O(n)
where PBFT is O(n²). O(n) view-change is the killer feature for
large validator sets.

**(d) Timing.** Partial synchrony. Responsive — decides as fast as
the network allows (not tied to worst-case timeout like PBFT).

**(e) Our analogue.** **Message complexity matches (both O(n)), but
semantics differ.** We tally 23 bits, HotStuff aggregates 2f+1
signatures. Both are O(n) but our "messages" are local memory reads,
HotStuff's are RPCs. The useful takeaway from HotStuff for us:
**threshold signatures**. If each chromosomal pair were signed by an
independent key (e.g., one per hardware-rooted enclave, or one per
hash-chain generation), a threshold-16 aggregate signature over the
23 votes would be a **non-forgeable quorum proof** verifiable by
external parties. This is the lowest-LOC uplift from "integrity
witness" to "cryptographic Byzantine witness" — see §6.

**What HotStuff defeats that we don't.** Distributed Byzantine
validators, plus produces a **publishable proof** that the agreement
happened. Our quorum leaves no artifact — nobody outside trust.ko
can verify the vote actually occurred.

### 2.9  HoneyBadgerBFT + Dumbo — Asynchronous BFT

**(a) Primary reference.**
Andrew Miller, Yu Xia, Kyle Croman, Elaine Shi, Dawn Song,
*The Honey Badger of BFT Protocols*, CCS 2016, pp. 31-42.
Bingyong Guo, Zhenliang Lu, Qiang Tang, Jing Xu, Zhenfeng Zhang,
*Dumbo: Faster Asynchronous BFT Protocols*, CCS 2020, pp. 803-818.
Background: Cachin-Kursawe-Petzold-Shoup, *Secure and Efficient
Asynchronous Broadcast Protocols*, CRYPTO 2001.

**(b) Failure model.** Byzantine, **fully asynchronous** (no GST
assumption). Uses randomized Byzantine Agreement + asynchronous
common subset (ACS) from BKR 1994 (Ben-Or-Kelmer-Rabin).

**(c) Message complexity.** O(n²) per batch (HoneyBadger) or
O(n log n) amortized (Dumbo).

**(d) Timing.** **Asynchronous** — no timing assumptions whatsoever.
Tolerates adversarially-controlled network.

**(e) Our analogue.** **No.** We operate synchronously per boot cycle,
per ioctl invocation, inside one kernel context — we don't even
have an asynchronous channel to be asynchronous over.

**What HoneyBadger defeats that we don't.** Adversarial network
timing. Not relevant to us (we have no network).

### 2.10  Dispersed Ledger / Rollup DA Layers 2023-2026

**(a) Primary references.**
- Data Availability Sampling: Mustafa Al-Bassam, *Fraud and Data
  Availability Proofs*, EthCC 2018; Ethereum EIP-4844 "Proto-Danksharding"
  2024.
- KZG polynomial commitments: Aniket Kate, Gregory M. Zaverucha, Ian
  Goldberg, *Constant-Size Commitments to Polynomials and Their
  Applications*, ASIACRYPT 2010.
- Erasure codes in DA: Yu-Li-Sekniqi-Gupta-Sirer, *Coded Merkle
  Tree: Solving Data Availability Attacks in Blockchains*, FC 2020.
- Celestia: Mustafa Al-Bassam, *LazyLedger / Celestia*, arXiv:1905.09274
  + whitepaper v2, 2023.
- EigenDA: EigenLayer whitepaper v2, 2024.

**(b) Failure model.** Byzantine + data-withholding. Uses erasure
coding + random sampling to ensure *everyone has access to data*
without trusting any single publisher.

**(c) Message complexity.** O(√n) samples per light client
(1-probabilistic availability check), O(n) for full reconstruction.

**(d) Timing.** Depends on base layer; typically partially synchronous.

**(e) Our analogue.** **Not meaningful.** We don't have a DA problem
— all our data is local to one machine. The nearest relevance is
**S72-γ's measured boot**: PCR-11 values attest that a specific set
of bytes were loaded into the kernel. That's the closest we get to
"data availability proofs." If we ever extend the quorum to run over
multiple ARCHWINDOWS machines (clustered AI agents, §7), DA becomes
relevant — but not today.

---

## 3. The `trust_quorum` Code, Line-by-Line, Against the Threat Model

Reading `trust/kernel/trust_quorum.c:69-120` (the `trust_quorum_vote`
function) carefully.

### 3.1  What the vote does mechanically

For each of 23 pairs `(a_segments[i], b_segments[i])`:
1. Mix `(a, b, field_id, subject_id, pair_idx)` with Fibonacci hash
   (`hash_64` from `linux/hash.h`, golden-ratio multiplier
   `0x9e3779b97f4a7c15ULL`).
2. Fold top 32 bits into bottom, then top 16 into bottom.
3. Take the LSB as the "opinion bit" for that pair.
4. Tally 23 bits into `votes[0]` and `votes[1]`.
5. `majority_bit = argmax(votes)`, `agree = max(votes)`.
6. Verdict:
   - `agree >= 16` → `MAJORITY` (~2/3 of 23 = 15.33, ceiling 16)
   - `8 <= agree <= 15` → `DISPUTED`
   - `agree < 8` → `APOPTOSIS_CANDIDATE`

### 3.2  What it detects

This is structurally a **chi-square test against the null
hypothesis that the 23 pairs are uncorrelated**. If the segments
were random, E[agree] = 11.5 by construction (23 independent fair
coins, conditional on taking the max-vote side has expected value
11.5 + sqrt(23)/π/2 ≈ 12.8). Getting 16+ agreements is about **2.6σ
above chance**, equivalent to p ≈ 0.005.

**What this detects in practice:** segments that are *internally
correlated* — which they should be, because the chromosomal model
says all 23 A-segments are different hash projections of the *same*
underlying behavioral DNA. If the subject's behavior is consistent,
most pairs should vote the same way. If one pair is corrupted
(rowhammer, bit-flip, memory pressure forcing wrong page-in), the
vote likely still passes 16+ because the other 22 pairs still agree.

**This is a real property!** Just not Byzantine tolerance.

### 3.3  Explicit threat-model table

| Threat | Capability | Does quorum detect? |
|--------|-----------|---------------------|
| Cosmic-ray bit flip in 1 segment | Random 1-bit flip | Yes — 22/23 still vote true, 22 ≥ 16 |
| Rowhammer on 1 row aligned to 1 segment | Targeted bit-flip in 1 segment | Yes, same as above |
| Rowhammer on 1 row spanning multiple segments | Bit-flips in N ≤ 7 segments | Yes, up to N = 7 |
| Targeted rowhammer across 8+ segments | 8 coordinated flips | **No — becomes DISPUTED**, not APOPTOSIS |
| Targeted rowhammer across 12+ segments | Majority flip | **No — vote flips to attacker's favor** |
| Kernel-write CVE, adversary flips all 23 | Full memory write | **No** |
| User-space attacker via ioctl | Cannot write segments directly | N/A (upstream authz blocks) |
| Offline-disk attacker modifying stored state | Changes B-segments before boot | Partial — TPM PCR check (S72-γ) catches; quorum doesn't |
| Lying replica (Byzantine) | Replica A claims truth, replica B claims lie | **No, because all replicas are one struct** |
| Replay of old quorum result | Reuse past verdict | N/A — quorum isn't signed/published |

### 3.4  Who watches the watcher?

The Liskov-style "client doesn't trust the server" question is acute:
`trust.ko` is itself the *arbiter* of trust. When the quorum says
"MAJORITY", who verifies the quorum wasn't tampered with?

Currently: **nobody**. The sysfs counters (`/sys/kernel/quorum/*`) can
be read by root, and if compromised, read-once by a privileged user-
space watcher. But the watcher itself runs on the same kernel that's
under attack. This is the well-known TCB (Trusted Computing Base)
inflation problem — Anderson 2001, *Security Engineering*, chapter 6;
Lampson 2004, *Computer Security in the Real World*, ACM TOCS. The
fix is **externalization**: either (a) an off-machine verifier reads
the quorum counters via attested channel, or (b) the quorum result
is signed by a hardware key (TPM, HSM, enclave) and the signature is
checked externally. Without externalization, the quorum is only a
self-consistency check, not a security primitive.

---

## 4. PKI + Hash Chain Composability for Byzantine Uplift

The lowest-LOC path from the current quorum to a real cryptographic-
Byzantine witness uses **threshold signatures**. The idea:

1. At boot, the module computes 23 **independent** signing keys,
   one per chromosomal pair. The keys can be:
   - Deterministic per-seed derivatives (HKDF from the APE SEED).
   - Per-boot random (secure but loses offline verifiability).
   - Hardware-rooted — only feasible with 23 physical TPM keys, which
     no practical TPM has.

2. Each pair signs its opinion bit: `sig_i = Sign(key_i, (subject_id,
   field_id, opinion_bit_i, nonce))`.

3. Aggregate: a verifier collects all 23 signatures, checks each
   against its corresponding public key, and accepts if ≥16 signatures
   are valid for the same (subject_id, field_id, nonce) and agree on
   the opinion bit.

**Why this is stronger than the current quorum:** an attacker who
flips one segment must also forge the corresponding signature —
reducing to breaking the signature scheme (e.g., Ed25519, infeasible).

**Why it still doesn't give us full BFT:** the 23 signing keys still
live in the same kernel module. A kernel-write adversary with access
to the key material can sign arbitrary opinions. The strict uplift
requires **separate trust domains per key**, which in practice means:

| Domain | Example | Cost |
|--------|---------|------|
| Different processes (+ SCM_RIGHTS) | userspace helper per key | Low |
| Different seccomp sandboxes | Linux seccomp-BPF isolates | Low |
| Different user namespaces | unprivileged user ns per key | Low |
| Different kernel namespaces + cgroups | per-cgroup enclave | Medium |
| Different hardware enclaves (SGX/SEV/TDX) | Intel SGX v2, AMD SEV-SNP, Intel TDX | High, platform-dep |
| Different physical machines | clustered ARCHWINDOWS | Very high |

Each additional domain raises the attacker's required capability
count by one. Without any of these, all 23 "replicas" collapse to a
single trust domain and Byzantine tolerance is 0.

### 4.1  BLS threshold signatures for O(1) aggregate proof

A particularly clean construction: **BLS (Boneh-Lynn-Shacham) 2001**
threshold signatures. All 23 pairs sign the same message under a
shared BLS public key; the 23 signatures aggregate into **one
64-byte proof** verifiable by a single pairing check.

- Reference: Boneh-Lynn-Shacham, *Short Signatures from the Weil
  Pairing*, J. Cryptology 17(4):297-319, 2004.
- Threshold variant: Boldyreva, *Threshold Signatures, Multisignatures
  and Blind Signatures Based on the Gap-Diffie-Hellman-Group Signature
  Scheme*, PKC 2003.
- Library: blst (Supranational, 2021), BoringSSL BLS12-381 (Google,
  2023).

This is what HotStuff uses (§2.8). For us it would mean one aggregate
signature per chromosomal verdict, externally verifiable by any
party holding the group public key. **~400 LOC uplift** (blst is
kernel-unfriendly but userspace-helper over netlink is feasible).

### 4.2  Lamport one-time signatures for post-quantum

If the concern is post-quantum adversaries (Shor's algorithm breaks
ECDSA/BLS), **Lamport one-time signatures** (Lamport 1979, SRI tech
report) or their Merkle-tree extension **XMSS** (Buchmann-Dahmen-
Hülsing 2011, PQCrypto) provide post-quantum BFT construction.

- Primary: Leslie Lamport, *Constructing Digital Signatures from a
  One-Way Function*, SRI International CSL-98, October 1979.
- XMSS standard: RFC 8391, IRTF CFRG, 2018.
- Reference: Bernstein-Hopwood-Hülsing-Lange-Niederhagen-Papachristodoulou-
  Schneider-Schwabe-Wilcox-O'Hearn, *SPHINCS: Practical Stateless Hash-
  Based Signatures*, EUROCRYPT 2015.

Signature size is the downside (several KB per Lamport signature,
hundreds of bytes for XMSS). For our quorum — one signature per
chromosomal verdict, published once per subject-field per 1-second
interval — this is plausible overhead.

**Cost:** ~800 LOC + kernel crypto-API integration. Probably not worth
it today given the adversary model, but a clean path if the moat
needs post-quantum resistance.

---

## 5. Authority-Centralization Problem: Who Audits `trust.ko`?

This is the **Hofstadter strange-loop problem** (S73-F) applied to
consensus. Our authority root is a kernel module that votes on its
own verdicts. No external witness exists.

### 5.1  Four architectures for trust bootstrap

From Mickens-Howell-Parno (et al.), *Dark Patterns in Trusted
Computing* (CCS 2015), and BOLT/Bolt-on (Roy-Fingerhuth-Garfinkel,
USENIX Security 2016):

| Architecture | Root of trust | Who watches? |
|---|---|---|
| TCB in kernel | kernel itself | hypervisor / firmware |
| TPM-rooted | TPM quote + remote verifier | remote attestation service |
| Hardware enclave | CPU manufacturer's key | Intel/AMD/Arm attestation service |
| Distributed BFT | 2f+1 other machines | each other |

ARCHWINDOWS currently sits at (1), with S72-γ adding a *measurement*
layer via TPM PCR-11. S72-γ is valuable but limited: it only checks
**load-time** state, not runtime. The quorum runs at **runtime** but
is self-attested.

### 5.2  Minimum external witness

The cheapest useful external witness would be:

- `ai-control` daemon running in a **separate user namespace** (already
  present).
- Daemon **opens the kernel quorum counters** at boot.
- Daemon **cross-checks** the counters against an expected
  trajectory using the Markov model (S73-F, already wired in
  `trust_ape_markov.c:264`).
- If the counters deviate from expected, daemon **raises an alarm
  via algedonic bypass** (S74 Agent 8's `trust_algedonic.c`).

This is **~50 LOC** of additional logic in `ai-control/cortex/` and
gives us a "bone thrown to the watcher-watcher problem" without a
full trust redesign. It doesn't solve the problem (the daemon is
still on the same machine), but it raises the bar: a kernel-write
adversary must ALSO forge daemon observations.

---

## 6. Minimum LOC Delta to Byzantine Tolerance

Summary table:

| Level | Description | LOC delta | Adversary defeated |
|-------|-------------|-----------|-------------------|
| 0 | Current (integrity witness) | 0 | Silent memory corruption ≤ 7 segments |
| 1 | Sign each opinion bit with HMAC-SHA256 (per-pair key derived from SEED) | +80 LOC | Adversary who can flip memory but not read SEED |
| 2 | Sign with Ed25519 per-pair key | +180 LOC | Same + offline-verifiable |
| 3 | Aggregate with BLS threshold signature | +400 LOC | External verifier can check any vote |
| 4 | Hardware-rooted keys via TPM (one key per trust domain, max ~8 keys practical) | +600 LOC | Kernel-write bound by TPM sealing policy |
| 5 | Separate-process replicas (23 userspace daemons signing independently) | +1200 LOC | Adversary must escalate from one to 2f+1=16 processes |
| 6 | Distributed ARCHWINDOWS cluster (2f+1 machines vote) | huge | Real PBFT/HotStuff analog |

**Recommended trajectory for S75:**
- Level 1 (HMAC per-pair) as a **~80 LOC patch** that would land
  cryptographic binding to SEED. After S74, the trust.ko module
  already derives per-subject keys from APE SEED, so the
  infrastructure exists. This is the **honest minimum viable
  Byzantine-ish uplift**.
- Level 2-3 deferred to S76+ based on whether external verifiability
  becomes a product requirement (e.g., AI-cortex on a different
  machine wanting to verify local kernel quorum).
- Levels 4-6 are architectural — don't attempt without a concrete
  adversary justifying the cost.

### 6.1  Level-1 sketch (~80 LOC)

```c
/* trust_quorum.c — Level-1 HMAC uplift sketch */

static u8 g_quorum_hmac_key[TRUST_CHROMOSOME_PAIRS][32];
static bool g_quorum_keys_ready;

int trust_quorum_derive_keys(const u8 *ape_seed)
{
    /* HKDF-Expand from APE SEED into 23 per-pair keys */
    for (int i = 0; i < TRUST_CHROMOSOME_PAIRS; i++) {
        u8 info[16];
        snprintf(info, sizeof(info), "quorum-key-%d", i);
        hkdf_expand(ape_seed, TRUST_SEED_SIZE,
                    info, strlen(info),
                    g_quorum_hmac_key[i], 32);
    }
    g_quorum_keys_ready = true;
    return 0;
}

/* Replace trust_quorum_opinion_bit with HMAC-backed version */
static u32 trust_quorum_opinion_bit_hmac(u64 a, u64 b, u32 field_id,
                                        u32 subject_id, u32 pair_idx)
{
    u8 input[32], mac[32];
    memcpy(input+0,  &a, 8);
    memcpy(input+8,  &b, 8);
    memcpy(input+16, &field_id, 4);
    memcpy(input+20, &subject_id, 4);
    memcpy(input+24, &pair_idx, 4);
    hmac_sha256(g_quorum_hmac_key[pair_idx], 32, input, 28, mac);
    return mac[0] & 1;
}
```

**What this defeats:** an adversary who can read/write chromosomal
segments but cannot read `g_quorum_hmac_key[]`. For example, an
attacker exploiting a bug in a specific segment-update path (rather
than arbitrary kernel-write).

**What this does not defeat:** an attacker with full kernel-write
(who can read the keys). Real Byzantine tolerance requires
domain separation.

---

## 7. Implications for the Broader Roadmap

### 7.1  The paper's "Byzantine-tolerant authority" claim

The Roberts/Eli/Leelee 2026 Zenodo paper (DOI 10.5281/zenodo.18710335)
describes the 23-fold chromosomal redundancy as "Byzantine-robust".
After this review, **the honest statement is that we are Byzantine-
*shaped* but not Byzantine-*tolerant*** — the structure looks like
a 2f+1 BFT vote, but the replicas are not in separate trust domains.

Recommended paper-vs-implementation doc update (already a known gap
from MEMORY.md:`roa_paper_validation_tier_audit_and_s74_plan.md`):
add an explicit note that chromosomal redundancy provides **integrity-
witness** not **BFT**, with a pointer to this survey.

### 7.2  Clustered ARCHWINDOWS (S80+)

The trajectory that would make chromosomal voting *actual* BFT is:
run 3 ARCHWINDOWS machines, each computes its own opinion about each
field (possibly against local chromosomal state), aggregate opinions
via HotStuff or PBFT, land the aggregate as the shared verdict.
This is S80+ territory; useful to enumerate as an architectural
possibility but not to rush.

At that point the 23-pair vote becomes an **inner ring** (von Neumann
1956 intra-machine reliability) inside a 3-of-5 BFT outer ring
(Lamport 1982 inter-machine BFT). The two layers compose well —
this is exactly how biological immune systems layer innate
(chromosomal) + adaptive (antibody / inter-cell signaling) responses
in S74 Agent 9's "catalysis" framing.

### 7.3  AI cortex as external witness

The AI cortex (`ai-control/cortex/`) running in userspace is the
**natural candidate for the external witness**. It already reads
`/sys/kernel/quorum/*` counters, can cross-check them against its
Markov model, and can (via `trust_algedonic.c`, also S74 Agent 8)
bypass to raise alarms. Adding a **cortex-side replay protection +
ordering witness** would solve 60% of the "who watches the watcher"
problem at <100 LOC. This is an S75-small-tier item.

---

## 8. Citations (31 entries)

**Reliability, circuit fault tolerance**
1. J. von Neumann. *Probabilistic Logics and the Synthesis of Reliable
   Organisms from Unreliable Components*. In Shannon & McCarthy eds.,
   *Automata Studies*, Princeton University Press, 1956, pp. 43-98.
2. P. Gács. *Reliable Computation with Cellular Automata*. JCSS
   32(1):15-78, 1986.
3. P. Gács. *Reliable Cellular Automata with Self-Organization*. J.
   Statistical Physics 103:45-267, 2001.
4. P. Gács and J. H. Reif. *A Simple Three-Dimensional Real-Time
   Reliable Cellular Array*. JCSS 36(2):125-147, 1988.

**Byzantine Fault Tolerance**
5. M. Pease, R. Shostak, L. Lamport. *Reaching Agreement in the
   Presence of Faults*. JACM 27(2):228-234, 1980.
6. L. Lamport, R. Shostak, M. Pease. *The Byzantine Generals Problem*.
   ACM TOPLAS 4(3):382-401, 1982.
7. M. Castro, B. Liskov. *Practical Byzantine Fault Tolerance*. OSDI
   1999, pp. 173-186.
8. M. Castro, B. Liskov. *Practical Byzantine Fault Tolerance and
   Proactive Recovery*. ACM TOCS 20(4):398-461, 2002.
9. M. Yin, D. Malkhi, M. Reiter, G. Gueta, I. Abraham. *HotStuff: BFT
   Consensus with Linearity and Responsiveness*. PODC 2019.
10. A. Miller, Y. Xia, K. Croman, E. Shi, D. Song. *The Honey Badger
    of BFT Protocols*. CCS 2016, pp. 31-42.
11. B. Guo, Z. Lu, Q. Tang, J. Xu, Z. Zhang. *Dumbo: Faster Asynchronous
    BFT Protocols*. CCS 2020, pp. 803-818.
12. M. Ben-Or, B. Kelmer, T. Rabin. *Asynchronous Secure Computations
    with Optimal Resilience*. PODC 1994.

**Crash-Fault Consensus**
13. M. Fischer, N. Lynch, M. Paterson. *Impossibility of Distributed
    Consensus with One Faulty Process*. JACM 32(2):374-382, 1985.
14. L. Lamport. *The Part-Time Parliament*. ACM TOCS 16(2):133-169,
    1998.
15. L. Lamport. *Paxos Made Simple*. ACM SIGACT News 32(4):51-58,
    2001.
16. D. Ongaro, J. Ousterhout. *In Search of an Understandable Consensus
    Algorithm*. USENIX ATC 2014, pp. 305-319.
17. D. Ongaro. *Consensus: Bridging Theory and Practice*. PhD thesis,
    Stanford University, 2014.

**Blockchain / Nakamoto**
18. S. Nakamoto. *Bitcoin: A Peer-to-Peer Electronic Cash System*.
    2008. https://bitcoin.org/bitcoin.pdf
19. J. Garay, A. Kiayias, N. Leonardos. *The Bitcoin Backbone
    Protocol: Analysis and Applications*. EUROCRYPT 2015.
20. I. Eyal, E. G. Sirer. *Majority Is Not Enough: Bitcoin Mining Is
    Vulnerable*. FC 2014.
21. R. Pass, L. Shi, E. Shi. *The Sleepy Model of Consensus*.
    EUROCRYPT 2017.
22. V. Bagaria, S. Kannan, D. Tse, G. Fanti, P. Viswanath. *Prism:
    Deconstructing the Blockchain to Approach Physical Limits*. CCS
    2019.

**Data Availability / Rollups**
23. M. Al-Bassam, A. Sonnino, V. Buterin. *Fraud and Data Availability
    Proofs*. arXiv:1809.09044 → FC 2021 version.
24. M. Yu, V. Sekniqi, P. Li, H. Gupta, E. G. Sirer. *Coded Merkle
    Tree: Solving Data Availability Attacks in Blockchains*. FC 2020.
25. M. Al-Bassam. *LazyLedger: A Distributed Data Availability Ledger
    With Client-Side Smart Contracts*. arXiv:1905.09274.
26. A. Kate, G. M. Zaverucha, I. Goldberg. *Constant-Size Commitments
    to Polynomials and Their Applications*. ASIACRYPT 2010.

**Cryptographic primitives**
27. D. Boneh, B. Lynn, H. Shacham. *Short Signatures from the Weil
    Pairing*. J. Cryptology 17(4):297-319, 2004.
28. A. Boldyreva. *Threshold Signatures, Multisignatures and Blind
    Signatures Based on the Gap-Diffie-Hellman-Group Signature Scheme*.
    PKC 2003.
29. L. Lamport. *Constructing Digital Signatures from a One-Way Function*.
    SRI CSL-98, October 1979.
30. J. Buchmann, E. Dahmen, A. Hülsing. *XMSS — A Practical Forward
    Secure Signature Scheme Based on Minimal Security Assumptions*.
    PQCrypto 2011. Standardized as IETF RFC 8391 (2018).
31. D. Bernstein, D. Hopwood, A. Hülsing et al. *SPHINCS: Practical
    Stateless Hash-Based Signatures*. EUROCRYPT 2015.

**Context / TCB**
32. R. Anderson. *Security Engineering*, 3rd ed., Wiley, 2020 (ch. 6,
    protection).
33. B. Lampson. *Computer Security in the Real World*. IEEE Computer
    37(6), 2004.
34. J. Mickens, J. Howell, B. Parno et al. *Dark Patterns in Trusted
    Computing*. CCS 2015.

---

## 9. Top 3 Findings (the TL;DR for the caller)

### Finding 1 — trust_quorum is CFT-flavored "integrity witness", not BFT

`trust_quorum_vote()` is a **chi-square-style consistency check** over
23 pseudo-independent hash projections of one `trust_subject_t`.
It catches **silent memory corruption up to 7 segments** (cosmic-
ray, rowhammer, single-pager-fail) with ~99.5% probability, giving
real, measurable reliability-theorem value in the von-Neumann-1956
sense. It does **not** defeat Byzantine adversaries because **all 23
"replicas" are fields of one struct in one kernel module** — any
kernel-write capability flips the whole vote. The verdict names
(MAJORITY, DISPUTED, APOPTOSIS) suggest BFT semantics; the
implementation delivers CFT-plus (crash + silent-corruption tolerance).
**Honest framing needed in the paper-vs-implementation doc.**

### Finding 2 — The watcher-watcher gap is the actual moat risk

The self-attestation problem — `trust.ko` validating its own quorum
— means that **a single kernel-write CVE breaks both the enforcement
and the monitoring** of the trust system. The S72-γ TPM attestation
layer catches load-time tampering but not runtime. The lowest-cost
uplift is a **userspace cortex-side witness** (~50-100 LOC): the
`ai-control` daemon (already in a separate process) reads
`/sys/kernel/quorum/*` counters, checks them against its Markov model
(already present as `trust_ape_markov.c`), and escalates via
algedonic bypass on deviation. This doesn't solve the trust-bootstrap
problem, but raises the adversary's required capability to
**kernel-write + cortex-process-compromise** — a meaningful
compound.

### Finding 3 — Level-1 HMAC uplift is the right S75 quorum item

The graduated LOC table in §6 identifies a clear ~80 LOC patch that
would provide **cryptographic binding** between chromosomal segments
and the APE SEED: per-pair HMAC-SHA256 keys derived via HKDF from
the SEED, used to compute each opinion bit via MAC instead of hash-
fold. This defeats adversaries who can flip segment memory but cannot
read SEED-derived keys — a realistic class (targeted memory-corruption
bugs, speculative-execution leaks of isolated pages, etc.) that is
much weaker than full kernel-write. **Level 1 is the honest minimum
viable uplift.** Levels 2-6 (Ed25519, BLS aggregate, TPM-backed,
process-separated, cluster-BFT) require progressively more
architecture and should be costed against concrete adversary
scenarios, not shipped speculatively.

**Bonus structural observation:** the header `trust_quorum.h`
declares `/sys/kernel/trust/quorum/*` but the code at line 194
registers `/sys/kernel/quorum` (no `trust/` prefix). Minor
documentation/code drift worth fixing when the daemon-side watcher
patch lands.

---

*End of S74-G.*
*Cross-refs: `trust/kernel/trust_quorum.c`, `trust/include/trust_quorum.h`,
`trust/kernel/trust_ape.c`, `docs/research/s73_a_von_neumann_gacs.md`,
`docs/research/s72_gamma_tpm2_attest.md`.*
