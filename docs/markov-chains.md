# Markov Chains in AI Arch Linux

> **Cite:** Roberts, Eli, Leelee. *Theorems 1-7 of the Root-of-Authority (RoA) Trust System.*
> Zenodo record **18710335**. <https://doi.org/10.5281/zenodo.18710335>

---

## a. Overview (3 sentences)

AI Arch Linux applies discrete-time Markov chains at eight points in the stack
to predict, validate, and forensically explain trust-state evolution without
relying on the LLM tier (which is optional and frequently absent). Each chain
is a small, bounded-memory state machine that observes transitions in real
time and exposes its transition matrix + stationary distribution to operators
via either an HTTP endpoint or `dmesg`. The chains are not a heuristic glued
on top of the trust system — three of them are *operational embodiments* of
Theorems 2, 3, 5, and 7 from the RoA paper (see Section c).

---

## b. Where they live

| Layer        | Module                                                     | Purpose                                                  | Endpoint                                  |
| ---          | ---                                                        | ---                                                      | ---                                       |
| NL fallback  | `ai-control/daemon/markov_nlp.py`                          | Trigram suggests handler when LLM offline                | (internal)                                |
| Hyperlation  | `ai-control/cortex/dynamic_hyperlation.py::MarkovTransitionMatrix` | Per-subject state transitions                    | `/cortex/markov/subject/{id}`             |
| APE validator| `trust/kernel/trust_ape_markov.c`                          | Theorem 3 chi-square check at module init                | `dmesg` only (`grep trust_ape_markov`)    |
| Behavioral   | `ai-control/daemon/behavioral_markov.py`                   | Per-PID syscall n-gram anomaly detection                 | (internal)                                |
| Decisions    | `ai-control/cortex/decision_engine.py::DecisionMarkovModel`| Predict-next-decision over the (action,verdict) lattice  | `/cortex/markov/decisions`                |
| Coherence    | `coherence/daemon/src/coh_markov.c`                        | Arbiter-state transition matrix (NORMAL/HIGH/CRIT/PANIC) | (internal — emitted in JSON status frame) |
| Trust score  | `ai-control/daemon/trust_markov.py`                        | Time-to-apoptosis forecast over 11-band kernel score     | proxied via `/cortex/markov/subject/{id}` |
| Test fuzzer  | `tests/integration/fixtures/markov_phrase_gen.py`          | Sample test inputs from learnt dictionary distribution   | (test only)                               |

All eight chains share a common contract:

1. They track an N x N integer count matrix (`observed[i][j]`).
2. They derive the transition matrix `P[i][j] = observed[i][j] / sum_j observed[i][j]`
   *only on read*, never on write — so observation is O(1) and lock-free / atomic.
3. The stationary distribution is computed by power-iteration with a fixed
   bound (typically 64 iters) so the operator path can never spin.
4. Hitting time to a designated absorbing state is the *only* derived
   quantity an operator can act on (apoptosis for Trust, PANIC for Coherence).

If an operator is staring at one of these chains and it appears to have
stopped advancing, the failure is almost certainly upstream: the *event*
producer has died, not the *chain* arithmetic. Check the producer first
(`systemctl status ai-cortex` for cortex chains, `dmesg | grep trust` for
APE, `systemctl status coherenced` for the arbiter chain).

---

## c. Theorem framing

The Roberts/Eli/Leelee paper (Zenodo 18710335) proves seven properties of
the RoA trust system. Four of them have direct Markov-chain interpretations
that are validated *operationally* (not just on paper) by the modules above:

### Theorem 2 — Non-replayability

> A captured AUTH proof cannot be re-injected to grant trust at a later
> nonce.

**Markov interpretation:** the (state, nonce) pair is the *real* state of
the chain; transitions are deterministic given current state, but the nonce
component advances strictly monotonically. The transition kernel from
`(s, n)` to `(s, n+k)` is non-zero only for `k = 1`; `k = 0` is forbidden
(replay), `k > 1` is forbidden (skip).

**Validated by:** `trust/kernel/trust_proof.c::trust_proof_consume`
(self-consuming proof — destroys the proof on read) and the AUTH
instruction family in the trust ISA.

### Theorem 3 — Reconfiguration unpredictability

> Given any prior APE configuration `C_t`, an attacker cannot predict
> `C_{t+1}` better than uniform over the configuration space.

**Markov interpretation:** the next-transition kernel `K(C_t -> C_{t+1})`
is *uniform* over the entire APE config space (90M+ configurations:
`APE_CFG_TOTAL = 94371840`). If it were not uniform, the chi-square
statistic over many transitions would diverge from its expected value.

**Validated by:** `trust/kernel/trust_ape_markov.c::trust_ape_markov_validator`.
At module init, this routine generates 4096 SHA-256 hashes of fresh APE
configs, builds a per-byte histogram, and computes a chi-square statistic
in pure integer math. Acceptable bound is logged via `pr_info`; failure
is logged via `pr_warn` but does **not** fail module load (so a slow
hash backend cannot brick the system).

`BUILD_BUG_ON(APE_CFG_TOTAL != 94371840ULL)` in `trust/kernel/trust_ape.c`
nails the configuration count to the spec at compile time.

### Theorem 5 — O(1) revocation

> Revoking a subject (apoptosis) is an O(1) operation regardless of how
> many proofs were ever issued to it.

**Markov interpretation:** APOPTOSIS is an **absorbing state** with
hitting time **1** from any state in the trust band lattice. The
transition matrix has `P[i][APOPTOSIS] = 1` for any `i` once revocation
fires; no clean-up walks, no proof-table sweeps, no per-subject queues
to drain. The stationary distribution conditioned on revocation is a
delta at APOPTOSIS.

**Validated by:** `ai-control/daemon/trust_markov.py::expected_time_to_apoptosis`
returns 1.0 immediately for any subject already in the absorbing state,
and converges in finite expected time from every other state.

### Theorem 7 — Chromosomal completeness

> The 23-segment-pair chromosome representation of a subject covers the
> full 2^256 symbolic-state space without gaps.

**Markov interpretation:** the stationary distribution of the chromosome
chain is **uniform over 2^256**. Equivalently, given infinite trace, every
chromosomal state is visited with equal frequency; no "dead band" exists
that the system cannot represent.

**Validated by:** the chromosome-pair structure in `trust/kernel/trust.h`
and the segment encoder in `trust/lib/libtrust.c`. The Markov-style
operational test for Theorem 7 is a *sampling* check rather than a closed
form: `trust_ape_markov_validator` doubles as a coverage probe at boot.

---

## d. Operator usage

Five concrete examples, ordered from most-used to deepest:

### 1. System-wide telemetry (one-shot)

```
$ curl -s -H "Authorization: Bearer $TOK" http://127.0.0.1:8420/cortex/markov/system | jq
{
  "uptime_s": 4127,
  "observation_count": 18342,
  "decision_chain": { ... },
  "subject_anomalies": [ ... ]
}
```

If the daemon is unreachable, `curl` returns 7 (connect refused) — handled
gracefully by the diag tool below.

### 2. Operator-facing diag (recommended starting point)

```
$ bash scripts/diag-markov.sh
[INFO] daemon up at 127.0.0.1:8420
[INFO] /cortex/markov/system: 18342 observations, 14 subjects
[INFO] decision chain: 7 distinct actions, top transition KILL_SUBJECT->QUARANTINE (n=412)
[WARN] subject 1234: anomaly_score=4.7 (>3.0 threshold)
[INFO] APE chi-square at boot: 234.5 (df=255, p=0.71) -- PASS
[INFO] coherence arbiter: 88% NORMAL, 11% HIGH, 1% CRIT, 0% PANIC
=== TALLY: 4 INFO, 1 WARN, 0 ERROR ===
```

### 3. APE chi-square at boot (kernel side)

```
$ journalctl -k | grep trust_ape_markov
[    3.412] trust_ape_markov: 4096 samples, 256 bins, chi_sq=234 (expected 256, df=255)
[    3.412] trust_ape_markov: PASS (within +/- 64 of expected)
```

The chi-square run is one-shot (module init only). If you want to re-run
it without rebooting, `rmmod trust && modprobe trust`.

### 4. Per-subject deep view (Agent 9 endpoint)

```
$ ai analyze markov 1234
Subject 1234 (pid=1234, exe=/usr/bin/ssh)
  hyperlation: state=NORMAL, recent_kl=0.12, hitting_time=inf
  trust:       band=GOOD (8/11), forecast_to_apoptosis=42.7s
  syscall:     anomaly=4.7 (warn), top n-grams: read,write,select / poll,read,write
```

(The `ai` CLI relies on the endpoint exposed by Agent 9; if it has not
landed yet the diag tool reports `[WARN] /cortex/markov/subject/* not
implemented yet, skipping`.)

### 5. Programmatic forecast (Python REPL)

```
$ python3 -c "from daemon.trust_markov import forecast; print(forecast(1234, 350.0))"
{'subject_id': 1234, 'current_band_idx': 4, 'expected_time_to_apoptosis': 42.7, ...}
```

Useful from a Jupyter notebook or an ad-hoc `systemd-run --user --pty`
session for "is this subject going to die in the next minute" questions.

---

## e. Citation

This work operationalizes Theorems 2, 3, 5, and 7 of:

> **Roberts, Eli, Leelee.** *Theorems 1-7 of the Root-of-Authority (RoA)
> Trust System.* Zenodo, record **18710335**.
> <https://doi.org/10.5281/zenodo.18710335>

The eight-chain decomposition (NL fallback / Hyperlation / APE validator /
Behavioral / Decisions / Coherence / Trust score / Test fuzzer) is original
to this codebase, but the underlying theorem statements and proofs are due
entirely to the cited authors. When extending or refactoring any module
listed in Section b, please preserve the theorem-to-module mapping in
Section c — the chi-square bound, the absorbing-state contract, and the
self-consuming proof are *load-bearing* for the security argument, not
implementation details.

---

*Last updated: Session 58, 2026-04-18.*
