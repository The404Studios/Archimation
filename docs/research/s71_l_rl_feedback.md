# S71-L — Reinforcement Learning / Feedback-Loop Learning for the AI Cortex (2024-2026)

**Agent:** Research Agent L (S71 12-agent push)
**Date:** 2026-04-20
**Scope:** Can ARCHIMATION's cortex learn from its own operation, and if yes, with what methods / what cost / what privacy posture?

---

## 0. What the cortex actually has today

Before talking about "add RL to it", the hard question is: what does "it" know right now?

| File                                              | What it is                                                                                                         | Current ML technique                                                         |
|---------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------|
| `ai-control/cortex/decision_engine.py` (936 LOC)  | Policy rules → heuristics → (optional) LLM. Returns `Verdict ∈ {ALLOW, DENY, QUARANTINE, ESCALATE, MODIFY}`.        | **Deterministic tree** + **bigram `DecisionMarkovModel`** (S68, lines 704-929). |
| `ai-control/cortex/dynamic_hyperlation.py` (79 KB) | Metabolic-state observer; surfaces `STEADY_FLOW / METABOLIC_STARVATION / BEHAVIORAL_DIVERGENCE`.                    | **4-state Markov transition matrix + KL divergence** on `dC/dt` flows.        |
| `ai-control/daemon/markov_nlp.py` (17 KB)         | Last-chance NL router when dictionary/regex/LLM all miss. `(tok_n-2, tok_n-1) → Counter[next]` + bigram emission.   | **Stdlib order-3 trigram with Laplace smoothing**. No neural net.             |
| `ai-control/daemon/behavioral_markov.py` (22 KB)  | Per-PID syscall trigram; anomaly score = log-likelihood z-score vs PID's own baseline.                              | **n=3 Markov, LRU 256 PIDs, FIFO 4096 ngrams**, Laplace α=0.01.               |
| `ai-control/daemon/trust_markov.py`               | 6-state trust-band chain with closed-form hitting time (Gauss-Jordan).                                              | **6×6 bigram transition matrix**.                                             |
| `ai-control/daemon/contusion_handlers.py` (165 KB)| `HANDLERS: dict[str, Callable]` — **121 entries** (line 2667 onwards), envelope `{success, handler_type, ...}`.     | No learning; statically typed dispatch.                                       |
| `ai-control/daemon/audit.py` (10 KB)              | Append-only `/var/log/ai-control/audit.jsonl` + in-memory ring buffer + hourly rotation at `_AUDIT_ROTATE_BYTES`.   | **Trace store already exists** — this is the offline-RL dataset on disk.     |

**Bottom line:** every learning component today is a Markov chain (bigram or trigram). There is **no gradient-based learning anywhere in the cortex**. But there *is* the raw material for one: `audit.jsonl` logs every routed call with timestamp, path, payload, and (via handler envelopes) success/failure. **121 handlers × structured logs × implicit trust-delta reward = a fertile offline-RL ground truth** — if we want to use it.

---

## 1. Learning-methods table, 2026

Ranked roughly by "setup pain for our pipeline".

| Method                          | Data needed                                       | Compute (train)                                  | Compute (infer)                  | Works offline? | Fit for ARCHIMATION                                                                                       |
|---------------------------------|---------------------------------------------------|--------------------------------------------------|----------------------------------|----------------|-----------------------------------------------------------------------------------------------------------|
| **Contextual bandits** (Thompson / LinUCB) | (context, arm, reward) tuples                     | **None — online update** in O(k) per call        | O(k) — k ≈ |handlers| ≤ 121      | Yes            | **Best-first** option. Zero new ML infra; just bookkeeping in `DecisionMarkovModel` or next to it.       |
| **Frequency-weighted n-grams** (kitchen-sink Markov) | Ambient route logs                                | Free — already happening                          | O(1) dict lookup                 | Yes            | We already do this 4× (decision, NL, syscall, trust). Extending n from 2→3 is cheap.                      |
| **Embedding retrieval** (sentence-transformers MiniLM, 22M params) | Past successful `(utterance, handler_type)` pairs | None — encode once, reuse                         | ~110 ms / query on Skylake (1K corpus) | Yes            | **Strong second pick.** No fine-tune, no training loop, works on CPU-only.                               |
| **Offline RL — Decision Transformer** [arXiv 2106.01345](https://arxiv.org/abs/2106.01345) | Return-conditioned (s,a,r) sequences              | 1–10 GPU-hrs on logged trajectories              | Transformer forward pass         | Yes            | Possible but heavyweight for "pick which of 121 handlers." Overkill unless we want multi-step planning.   |
| **Offline RL — IQL** [arXiv 2110.06169](https://arxiv.org/abs/2110.06169) | (s,a,r,s') quadruples                              | Few GPU-hrs; SOTA on D4RL                         | MLP forward                      | Yes            | Same verdict: powerful, but we don't have a clear "state/transition" — we have dispatches.               |
| **DPO** [arXiv 2305.18290](https://arxiv.org/abs/2305.18290) | `(prompt, chosen, rejected)` preference pairs     | 1–4 hrs LoRA on 24 GB for 7B; ~30 min for 1.5B   | LLM inference                    | Yes (local)    | For refining the *LLM* tier, if we ever load one. Doesn't help the rule/heuristic/handler layer.         |
| **KTO** [arXiv 2402.01306](https://arxiv.org/abs/2402.01306) | **Binary** good/bad signal per output (no pairs)  | Same as DPO, often better                         | LLM inference                    | Yes            | **More natural fit than DPO** — we'd have "user accepted" / "user corrected" signals, not A/B pairs.     |
| **ORPO** [arXiv 2403.07691](https://arxiv.org/abs/2403.07691) | Preference pairs, **no reference model**          | Single-pass SFT + preference in one loss         | LLM inference                    | Yes            | Cheapest of the DPO family; skip refs, one training loop.                                                 |
| **GRPO** (DeepSeek R1) [arXiv 2501.12948](https://arxiv.org/abs/2501.12948) | Group-sampled rollouts with rule-based rewards    | Heavy — AIME-style 15.6%→77.9% jump but days on H100 | LLM inference                | Not for us     | Nobody's running reasoning-grade RL on a 3B on a 4060 in under a week. Defer indefinitely.               |
| **RLHF (PPO)**                  | (prompt, response, reward model score)            | 10–100× DPO cost, unstable                        | LLM inference                    | Yes            | Eliminated by DPO/ORPO/KTO for small-scale setups. Don't bother.                                         |
| **LoRA fine-tune — Qwen2.5-1.5B** | 500-10K instruction pairs                         | **~30 min on RTX 4060 16 GB**                    | 5-15 tok/s CPU / 50+ tok/s 4060  | Yes            | Feasible on "new hw". Gets a task-specific router but cost/benefit vs retrieval is unclear until S72+.   |

**Key observation:** the three bottom rows (DPO/KTO/ORPO/GRPO) only apply if we intend to fine-tune an LLM. The cortex's real decision surface — "which of 121 handlers does this utterance map to?" — is classification, not generation. Contextual bandits + retrieval solve it directly.

---

## 2. What ARCHIMATION actually has that is fertile ground

### 2.1 The trace substrate already exists

`ai-control/daemon/audit.py` already writes every API call (minus polling endpoints, see its `_SKIP_PATHS`) to `/var/log/ai-control/audit.jsonl`. Rotation at `_AUDIT_ROTATE_BYTES`, one backup kept. That's a **running offline-RL dataset for free.**

Fields we get on every trace:
- **Context:** trust band, path, payload, timestamp, session id.
- **Action:** `handler_type` chosen (if dictionary/v2/markov routed).
- **Outcome:** handler envelope `{success: bool, handler_type, error?, ...}`.

### 2.2 Implicit rewards we can back out of the log

| Signal                                           | Polarity | Where it's already collected                                    |
|--------------------------------------------------|----------|------------------------------------------------------------------|
| Handler returned `success=true`                  | +        | envelope field, every call.                                      |
| Handler returned `success=false` with `error`    | −        | envelope field.                                                  |
| User re-asks within 30 s (timestamp delta)        | weak −   | session id + audit timestamps.                                   |
| User says "no undo that", "cancel", "wrong"      | strong − | NL classifier; can add a dictionary pattern in 5 LOC.            |
| Trust score went up after the action             | +        | `dynamic_hyperlation.py` already tracks `dC/dt` — subscribe to it. |
| Trust score went down after the action           | −        | same.                                                            |
| Time between utterances is long (>N min)          | weak +   | user engaged and not frustrated; timestamp delta.                |
| Process apoptotic or quarantined after action     | strong − | trust kernel event; already on the event bus.                    |

**None of this requires user opt-in for data collection** — every signal is already in the machine's own logs. Opt-in is only relevant for **training a model from those logs**.

### 2.3 Handler catalogue is tiny (k ≤ 121)

Contextual-bandits literature assumes k ≤ 10⁴ arms is routine; we have k ≤ 121. Thompson-Sampling Beta posteriors: **~1 KB per arm + context hash**, online update O(k). **This is overkill-small for a bandit.**

---

## 3. Realistic plan — S72 → S76 runway

### S72 — contextual bandits layer on `DecisionMarkovModel` (0 new ML infra)

1. Add `BanditArm` dataclass next to `DecisionMarkovModel`:
   ```python
   @dataclass
   class BanditArm:
       handler_type: str
       alpha: float = 1.0    # Beta(α, β) Thompson prior
       beta: float = 1.0
       n_pulls: int = 0
       last_context_hash: int = 0
   ```
2. On every route: look at top-k candidates from dictionary/v2/markov, **sample** each from `Beta(α,β)`, pick max (Thompson).
3. On every handler envelope: `arm.alpha += 1` on success, `arm.beta += 1` on failure.
4. **Bounded memory** — at most 121 arms × ~80 bytes = 10 KB.
5. Persist to `/var/lib/ai-control/bandit.pkl` (same dir as markov models), atomic rename on flush.
6. **No behaviour change when uncertain** — bandit only kicks in when dictionary/v2 both miss; else the existing tiered router still wins. Bandit is a **last-mile disambiguator**, not a replacement.

Cost: ~200 LOC, no new deps, no training loop. Instrument success/failure. Collect 2 weeks of live traces. **Evaluate whether to graduate.**

### S73 — embedding retrieval (if bandits saturate)

If bandits plateau (e.g., the "cold-start" problem: new phrases with no history), add retrieval.

- Pre-compute MiniLM embeddings of all 6989 dictionary_v2 template phrases + all successful `(utterance, handler_type)` pairs from audit.jsonl.
- At query time: encode user utterance (≈22 M params, ~110 ms on Skylake with `sentence-transformers/all-MiniLM-L6-v2`), FAISS / numpy-cosine against corpus, retrieve top-k, pass to bandit.
- **No fine-tune** — just the pre-trained model.
- Adds ~100 MB disk, ~200 MB RAM. Affordable.

[MiniLM model card](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) — 22 M params, 384-dim embeddings, ~4k/sec encodings on CPU for short sentences.

### S74+ — LoRA fine-tune (only if retrieval plateaus)

At 2 weeks × ~1000 traces = 14 K examples, a LoRA fine-tune becomes marginally sensible. Cost estimate:

- Qwen2.5-1.5B base: ~3 GB on disk, runs CPU-only at 5-15 tok/s per [Hardware-Corner LLM DB](https://www.hardware-corner.net/llm-database/Qwen/).
- LoRA rank-16 adapter: ~50 MB adapter file, ~4-6 GB peak VRAM during train.
- **~30-60 min to train on RTX 4060 16 GB**; multiple hours on CPU; cloud: QLoRA single-H100 ~$10-16 for 8-12 hrs ([RunPod guide](https://www.runpod.io/articles/guides/how-to-fine-tune-large-language-models-on-a-budget)).
- Objective: **KTO** ([arXiv 2402.01306](https://arxiv.org/abs/2402.01306)) over binary good/bad envelope, *not* DPO, because our signal is binary success, not ranked preferences.
- Avoid catastrophic forgetting via **O-LoRA / rehearsal** ([ACL 2024](https://aclanthology.org/2024.acl-long.77/)) — replay 10% old traces every new epoch.

**Honest framing:** this is aspirational. We should only pull this trigger if S72 + S73 leave a clear gap.

---

## 4. Alternatives to RL that may beat it

| Alt                                         | Why it might beat RL                                                                                                            |
|---------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| **Kitchen-sink Markov** (n=2→4)             | We already run 4 Markov chains. Raising order costs ~10× RAM, no new infra, captures more long-range context.                   |
| **Frequency-weighted dictionary**           | Rank dictionary entries by historical success, pick top. Literally `sort(dict, key=success_rate)`. 20 LOC.                       |
| **Bayesian threshold tuning** (confidence in `dictionary_v2`) | Beta posterior on the 0.7 `AICONTROL_DICT_V2_THRESHOLD` value. One-dim bandit, closed form.                                   |
| **Embedding retrieval** (see S73)            | All the generalization of a learned model, zero training loop, private by construction.                                         |
| **DSPy / in-context optimization** [ICLR 2024](https://arxiv.org/abs/2310.03714) | Bootstrap few-shot examples from audit.jsonl, feed as ICL context to llama-cpp model. No weight updates, still "learns."         |

Netflix and most production recommenders **still run ε-greedy** despite fancier options being available ([Netflix bandit slides](https://www.slideshare.net/JayaKawale/a-multiarmed-bandit-framework-for-recommendations-at-netflix)), because operational simplicity dominates the marginal regret gain. We should borrow that discipline.

---

## 5. Old hardware vs new hardware

### Old hw (Skylake + 8 GB RAM, no discrete GPU)

| Method                  | Feasible? | Cost                                          |
|-------------------------|-----------|-----------------------------------------------|
| Contextual bandits       | Yes       | Negligible — already running bigger Markov chains. |
| Frequency n-grams        | Yes       | Already running.                              |
| Embedding retrieval      | Yes       | ~110 ms/query on CPU, 1 K corpus. Acceptable. |
| LoRA fine-tune 1.5B     | No (would take days) | Skip.                                |
| LoRA fine-tune 3B        | No        | Skip.                                         |

### New hw (Ryzen + RTX 4060 16 GB or 4070 Ti Super 16 GB)

| Method                  | Feasible? | Cost                                          |
|-------------------------|-----------|-----------------------------------------------|
| Everything above         | Yes       | Same.                                         |
| LoRA fine-tune Qwen2.5-1.5B | **Yes — <1 hr** | 50-200 MB adapter, 4-6 GB VRAM peak. |
| LoRA fine-tune Qwen2.5-3B | Yes — 1-3 hrs | 8-12 GB VRAM peak.                     |
| QLoRA fine-tune 7B       | Yes — 4-8 hrs  | 12-14 GB VRAM; 24 GB card preferred.  |

---

## 6. Privacy + local-only posture

**Non-negotiable design constraints** (S71 privacy hat on):

1. All trace collection stays on device (`/var/log/ai-control/audit.jsonl`, already local).
2. No cloud telemetry. Ever. Not even model weights get uploaded — Qwen2.5, Phi-4, MiniLM are pulled via package manager at install and never re-contact the cloud.
3. Training data (the jsonl) is `root:root 0600` — only root + ai-control daemon can read it.
4. **User opt-in before any trace is used for training**, default **off**. Collection is fine (needed for diagnostics), but moving traces into a training corpus requires an explicit `aictl learn enable` command.
5. Adapters trained on a user's traces live in `~/.cache/ai-control/adapters/<sha256-of-trace-window>.safetensors` — never shared.
6. **Trust-kernel gating** on the learning pipeline itself: the offline trainer runs at `TRUST_USER` (not `TRUST_INTERACT`), and must present an APE proof that the trace window it's reading was written by the same UID.

---

## 7. Cost analysis — fine-tune Qwen2.5-1.5B on 1000 user traces

Per [Qwen docs](https://qwen.readthedocs.io/en/v2.5/benchmark/speed_benchmark.html) + [RunPod 2026 guide](https://www.runpod.io/articles/guides/how-to-fine-tune-large-language-models-on-a-budget) + [Spheron 2026 guide](https://www.spheron.network/blog/how-to-fine-tune-llm-2026/):

**Target:** 1000 `(utterance, handler_type)` pairs, LoRA rank-16, KTO objective.

| Hardware                               | Feasible? | Wall time | VRAM peak | Adapter size |
|----------------------------------------|-----------|-----------|-----------|---------------|
| RTX 4060 16 GB (new hw spec)            | Yes       | **~25-35 min** | ~6 GB | 30-80 MB |
| RTX 4090 24 GB                          | Yes       | ~8-15 min | ~4 GB     | 30-80 MB    |
| CPU-only (Ryzen 7 5800X, 32 GB RAM)     | Yes       | ~6-12 hrs | ~8 GB RAM | 30-80 MB    |
| Integrated iGPU (8 GB shared RAM)       | Marginal  | ~12-24 hrs | ~7 GB RAM | 30-80 MB   |

**Verdict:** Qwen2.5-1.5B on 1000 traces is **1 hour of wall time on any 8+ GB discrete GPU, or overnight on CPU.** It's fine. The blocker is not compute; the blocker is whether we have 1000 non-redundant traces and a signal to train against.

---

## 8. Don't fine-tune, just retrieve — the DSPy / ICL angle

[DSPy (ICLR 2024)](https://arxiv.org/abs/2310.03714) and the broader "compiled prompt" research line demonstrate that **on classification-shaped tasks, retrieving the nearest past trace and dropping it into the LLM context is within a few % of fine-tuning, with 0 training infra.**

For ARCHIMATION specifically:
- Encode all successful traces once (~11 K short utterances × 384 dims × float32 = ~17 MB).
- At inference: encode user utterance, retrieve top-5, feed to the small LLM as `f"Past similar requests: {traces}. Current: {utt}. handler_type =?"`.
- If no LLM loaded, skip to "top-1 retrieval wins".
- 100% local, no training, no catastrophic forgetting, **updates instantly** on new success.

**This is probably the right S73 move even if bandits are "enough"**, because it gives us ICL-style generalization without ever fine-tuning.

---

## 9. Recommendation

**S72 action items (one-session scope):**

1. Add `BanditArm` + `HandlerBanditModel` class alongside `DecisionMarkovModel` in `ai-control/cortex/decision_engine.py`. ~200 LOC. Thompson-Sampling / Beta posteriors. Bounded memory 121 × 80 bytes = 10 KB.
2. Instrument `contusion.py:_route_*` to call `bandit.update(handler_type, success)` on every envelope return. Defensive try/except — one bad arm must not poison routing.
3. **Hook the signal sources already in the logs:**
   - `audit.jsonl` writer already in place.
   - Handler envelope `success` bool is the primary reward.
   - Short-gap re-ask detection: 20 LOC new helper in `contusion.py` scanning last 30 s of audit ring buffer.
4. `/cortex/bandit` read-only endpoint in `cortex/api.py` for telemetry (top arms, regret, pull counts).
5. Persist `/var/lib/ai-control/bandit.pkl` on graceful shutdown, load on start. Never block startup on load failure.
6. Pytest: **11-22 new tests** in `tests/integration/test_bandit.py` — arm creation, reward update, Thompson sampling deterministic with fixed seed, persistence round-trip, degrade-gracefully on empty state.

**Decision gate for S73 (retrieval):** after 2 weeks of live traces on real hardware, measure:
- % of routes where bandit chose top-dictionary candidate (= bandit adds no value; skip retrieval).
- % of routes where bandit picked differently (= bandit is learning; probably keep bandit + stop here).
- % of routes with no bandit history (cold starts) (= need retrieval or ICL).

**Decision gate for S74 (LoRA fine-tune):** only if cold-start rate > 30% after retrieval is in place, or if a specific handler class is systematically mis-routed, and then target **KTO** objective on Qwen2.5-1.5B with O-LoRA continual layering. Not before.

**Anti-goals:**
- Do **not** bring in PPO / RLHF / GRPO. Wrong scale, wrong problem shape.
- Do **not** fine-tune before bandits + retrieval. Order matters.
- Do **not** upload anything. Ever.

---

## 10. 400-word executive summary

The cortex is 100% Markov today (five chains: `DecisionMarkovModel`, `dynamic_hyperlation`, `markov_nlp`, `behavioral_markov`, `trust_markov`). No gradient learning anywhere. This is fine — Markov is lightweight, bounded-memory, and interpretable, which are all virtues for a trust-enforcing daemon. But **we are sitting on a rich offline-RL dataset we're not using**: `/var/log/ai-control/audit.jsonl` already records every routing decision with `success`/`error` envelopes (121 handlers, structured), and `dynamic_hyperlation` already exposes trust-delta as an implicit reward signal.

The space of learning methods in 2026 is: RLHF (superseded by DPO [2305.18290](https://arxiv.org/abs/2305.18290), KTO [2402.01306](https://arxiv.org/abs/2402.01306), ORPO [2403.07691](https://arxiv.org/abs/2403.07691)), offline RL (Decision Transformer [2106.01345](https://arxiv.org/abs/2106.01345), IQL [2110.06169](https://arxiv.org/abs/2110.06169)), reasoning-grade RL (GRPO / DeepSeek-R1 [2501.12948](https://arxiv.org/abs/2501.12948)), contextual bandits (classical, production-proven at Netflix), and embedding retrieval (MiniLM + cosine). For our actual problem — "pick one of 121 handlers given an utterance" — **contextual bandits with Thompson-Sampling Beta posteriors dominate the pareto frontier**: ~10 KB RAM, online update, no training loop, no new deps, and they naturally handle the success/failure reward already on the envelope.

Recommendation for **S72**: add a `HandlerBanditModel` next to `DecisionMarkovModel` in `decision_engine.py` (~200 LOC, zero new infrastructure), instrument every route with an arm update, persist to `/var/lib/ai-control/bandit.pkl`, expose `/cortex/bandit` telemetry. The bandit runs as a last-mile disambiguator when dictionary + dictionary_v2 disagree; it does not replace the existing tiered router. Collect 2 weeks of production traces.

**S73**, if bandits saturate on cold-start: add embedding retrieval (`sentence-transformers/all-MiniLM-L6-v2`, 22 M params, ~110 ms/query CPU on 1K corpus). **S74+**, if retrieval saturates: LoRA fine-tune Qwen2.5-1.5B with KTO on 1000 user traces — feasible in ~30 min on an RTX 4060 or overnight on CPU. Adapter size 30-80 MB.

**Privacy is non-negotiable:** traces stay on device, `root:root 0600`, opt-in for training, trust-kernel gated. No telemetry, ever. The user's 1000 traces never leave `/var/log`.

**The order matters.** Bandits → retrieval → fine-tune. Don't skip steps. Every level up costs more infrastructure; measure the gap before you pay for the next rung.

---

## Sources

- [Direct Preference Optimization (Rafailov et al. 2023) — arXiv 2305.18290](https://arxiv.org/abs/2305.18290)
- [KTO: Model Alignment as Prospect Theoretic Optimization — arXiv 2402.01306](https://arxiv.org/abs/2402.01306)
- [ORPO: Monolithic Preference Optimization — arXiv 2403.07691](https://arxiv.org/abs/2403.07691)
- [DeepSeek-R1 / GRPO — arXiv 2501.12948](https://arxiv.org/abs/2501.12948)
- [Decision Transformer — arXiv 2106.01345](https://arxiv.org/abs/2106.01345)
- [Implicit Q-Learning (IQL) — arXiv 2110.06169](https://arxiv.org/abs/2110.06169)
- [DSPy (ICLR 2024) — arXiv 2310.03714](https://arxiv.org/abs/2310.03714)
- [Mitigating Catastrophic Forgetting via Self-Synthesized Rehearsal — ACL 2024](https://aclanthology.org/2024.acl-long.77/)
- [sentence-transformers/all-MiniLM-L6-v2 — HuggingFace](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2)
- [Qwen LLM hardware-requirements DB](https://www.hardware-corner.net/llm-database/Qwen/)
- [Qwen2.5 Speed Benchmark](https://qwen.readthedocs.io/en/v2.5/benchmark/speed_benchmark.html)
- [RunPod LoRA/QLoRA cost guide 2026](https://www.runpod.io/articles/guides/how-to-fine-tune-large-language-models-on-a-budget)
- [Spheron "How to fine-tune LLMs in 2026"](https://www.spheron.network/blog/how-to-fine-tune-llm-2026/)
- [Netflix multi-armed bandit framework](https://www.slideshare.net/JayaKawale/a-multiarmed-bandit-framework-for-recommendations-at-netflix)
- [Scalable and Interpretable Contextual Bandits — arXiv 2505.16918](https://arxiv.org/html/2505.16918v1)
- [Thompson Sampling in Partially Observable Contextual Bandits — arXiv 2402.10289](https://arxiv.org/abs/2402.10289)
- [LlamaFactory (Phi-4 + Qwen2.5 fine-tune)](https://github.com/hiyouga/LlamaFactory)
- [Should I Use Offline RL or Imitation Learning? — BAIR blog](https://bair.berkeley.edu/blog/2022/04/25/rl-or-bc/)
