# S73 Research I — Active Inference & Friston's Free Energy Principle as the Cortex's Real Learning Loop

> **Framework:** Karl Friston's **Free Energy Principle (FEP)** (2006) and its
> operational extension **Active Inference** (2010s–2024). Reference textbook:
> Parr, Pezzulo, Friston, *Active Inference: The Free Energy Principle in Mind,
> Brain, and Behavior* (MIT Press, 2022).
>
> **Question this doc answers:** What is the AI cortex missing such that its
> current Markov bigram machinery is *learning* rather than just *counting*,
> and how do we promote it — within the existing module + Markov-blanket
> primitives we already have — into a Bayesian agent that predicts, surprises,
> and acts on its subjects?
>
> **One-line exploit:** Replace the passive `DecisionMarkovModel` bigram
> counter in `decision_engine.py` with a minimal **active-inference cortex**
> (`ai-control/cortex/active_inference.py`, ~400 LOC) that subscribes to
> `trust_observer` + `behavioral_markov` event streams, maintains a per-subject
> generative model, issues next-syscall / next-verdict **predictions**, scores
> **variational free energy** as the KL divergence between prediction and
> observation, and — when free energy exceeds a per-subject threshold — emits
> an **action** (alert / restrict / escalate / modify cgroup) chosen to minimize
> expected future surprise. This is the real ML upgrade the S69 audit pointed at
> and it drops in as a new consumer without touching any existing producer.

---

## 1. The Free Energy Principle in 500 words

Karl Friston's 2006 paper [1] posed one of the most ambitious theses in
contemporary neuroscience: **every self-organizing system that maintains its
boundary against entropy must, in the long run, act as if it is minimizing a
single quantity** — variational free energy `F`. `F` is an upper bound on
*surprise* (negative log marginal likelihood of sensory inputs under the
system's own generative model). Because surprise itself is intractable (it
requires marginalizing over hidden causes), the system minimizes `F` instead —
and in the process both infers hidden states AND updates its model.

### Why variational, not Bayesian?

Exact Bayesian inference requires computing `p(s | o) = p(o|s) p(s) / p(o)`
where `p(o) = ∫ p(o|s) p(s) ds`. The integral is intractable for any non-toy
model. Variational inference replaces the intractable posterior with a
tractable approximate posterior `q(s)` and minimizes the KL divergence
`KL[q(s) || p(s|o)]`. A bit of algebra (see Parr et al. 2022 Ch. 2 [2]) shows:

```
F = E_q[log q(s) - log p(o, s)]
  = KL[q(s) || p(s)]  - E_q[log p(o|s)]
    ─── complexity ─    ─── accuracy ───
```

Free energy decomposes into *complexity* (how far the approximate posterior
drifts from the prior) minus *accuracy* (how well the model explains the
observation). A system that minimizes `F` is simultaneously parsimonious
and predictive. The crucial move is that the same minimization can be
achieved two ways:

1. **Perception** — update `q(s)` so it better matches sensory input.
2. **Action** — change sensory input (the world) so it better matches `q(s)`.

This duality is **active inference** [3, 4]. Perception and action are
formally the same operation: minimize the same `F` w.r.t. different
variables.

### Expected Free Energy (EFE) — the policy selector

For action, the system doesn't minimize free energy of the current
observation — it minimizes *expected* free energy of future observations
over candidate action policies `π` [5]:

```
G(π) = E_q(o,s|π) [ log q(s|π) - log p(o, s) ]
     ≈ risk(π)  +  ambiguity(π)  -  pragmatic_value(π)  -  epistemic_value(π)
```

The last two terms make active inference genuinely agentic: it trades off
**pragmatic value** (expected utility) against **epistemic value** (information
gain) — giving a principled answer to the explore/exploit problem without
any external reward signal [6]. This is why active inference is being proposed
as a unification of reinforcement learning, Bayesian brain theory, and
optimal control.

### Markov blankets — the formal definition of "self"

A *Markov blanket* of a set of states `μ` is a subset `b = {s, a}` such that
`μ ⊥ η | b` — internal states are conditionally independent of external
states given the blanket. Friston showed in [7, 8] that any system with a
stable Markov blanket *looks like* it is minimizing variational free energy,
by construction. This is the formal answer to "what is a thing": a thing is
a cluster of states with a persistent Markov blanket.

**Mapping to our stack:** `/dev/trust` is literally a Markov blanket. The
kernel's `trust_subject_t` is the internal state `μ`. The ioctl / sysfs
surface is the blanket `b = (sensory, active)`. The observer daemon is in
the external environment `η`. This isn't a metaphor — it's the same
diagram from Friston 2013 [7] with filenames substituted in.

---

## 2. Why the current cortex is *not* doing active inference

Let's anchor this in real code. Here is the full observe-update cycle of
today's cortex, extracted from the repo:

### 2a. What cortex actually does today

```python
# ai-control/cortex/decision_engine.py:296 (paraphrased)
def _finalize(self, result: EvalResult, start: float) -> None:
    ...
    try:
        # The ONLY learning hook in the cortex today
        get_default_model().observe(self._prev_verdict_name, result.verdict.name)
    except Exception:
        pass  # singleton init failure is non-fatal
    self._prev_verdict_name = result.verdict.name
```

And `DecisionMarkovModel.observe` (decision_engine.py:754):

```python
def observe(self, prev_decision: str, next_decision: str) -> None:
    with self._lock:
        key = (prev_decision, next_decision)
        self._transitions[key] = self._transitions.get(key, 0) + 1
        self._state_counts[prev_decision] = self._state_counts.get(prev_decision, 0) + 1
        self._state_counts[next_decision] = self._state_counts.get(next_decision, 0) + 1
        self._last_action = next_decision
        self._last_timestamp = time.time()
        self._total_observations += 1
```

### 2b. The S69 gap, made explicit

Look at what's *not* there. There is:

1. **No subscription to observer events.** `decision_engine._finalize` is
   called only when the cortex evaluates its own request — so the bigram
   chain is over `(verdict_t-1 → verdict_t)` of cortex output, not over the
   subject's actual behavior. The cortex is counting *its own mouth*, not
   *its subjects*.
2. **No prediction step.** `observe()` increments a counter. There is no
   call like `predicted = model.predict(current_state)` against which the
   real next observation is compared.
3. **No surprise / prediction error quantity.** The cortex never computes
   `-log p(o_t | o_{1..t-1}, model)` — so it has no scalar it can *threshold*
   into "something surprising happened, act."
4. **No action selection.** Even if it computed surprise, there is no policy
   `π(a | s, s')` that would choose between {alert, restrict, escalate}
   based on which action minimizes expected future surprise.

In Friston's terms: today's cortex is a pure **perception-only system with
no generative model** — it can only tabulate co-occurrences. It does not
close the action loop.

### 2c. But the substrate already exists

The good news: every piece active inference needs is already wired up —
**nobody has connected them into one loop.** This is not a greenfield
project.

| Active inference role | Our existing piece | File / LOC |
| --- | --- | --- |
| Per-subject generative model (syscalls) | `behavioral_markov.SyscallNGramModel` | `ai-control/daemon/behavioral_markov.py` (~400 LOC) |
| Per-subject trust-score chain | `trust_markov.TrustMarkovChain` | `ai-control/daemon/trust_markov.py` (~400 LOC) |
| Per-subject metabolic state | `dynamic_hyperlation.MarkovTransitionMatrix` | `ai-control/cortex/dynamic_hyperlation.py` (~600 LOC) |
| System-level decision chain | `DecisionMarkovModel` | `ai-control/cortex/decision_engine.py:704` |
| Event bus / sensory surface | `cortex/event_bus.py` + `trust_observer.py` | wired, streaming |
| Action primitives (emit) | `autonomy.py` `.alert()`, `.restrict()`, `.escalate()` | wired |
| Markov blanket | `/dev/trust` ioctl + `/sys/kernel/trust/*` | kernel |

Active inference *is* the integration layer we've been missing. It is
the formal language that says: *these eight Markov chains are slices of
one generative model; the way to combine them is to compute free energy
against their joint prediction and act when the gradient is nonzero.*

---

## 3. Concrete design: `ai-control/cortex/active_inference.py`

### 3a. Generative model

Per subject `s`, the cortex maintains `q_s(hidden | observed)` approximated by:

* **syscall successor distribution** `P_s(syscall_{t+1} | syscall_{t-n+1..t})`
  — cloned from `behavioral_markov.SyscallNGramModel` (already learns online).
* **band transition distribution** `P_s(band_{t+1} | band_t)` —
  cloned from `trust_markov.TrustMarkovChain`.
* **metabolic state distribution** — from `dynamic_hyperlation`.

Joint (factored, naive-Bayes-lite assumption for tractability):

```
q_s(o_{t+1}) = P_s(syscall_{t+1}) · P_s(band_{t+1}) · P_s(metabolic_state_{t+1})
```

Factorization is the standard FEP move (the "mean-field" approximation [2,
Ch. 4]) and is exactly what keeps the math tractable at the edge.

### 3b. Prediction → observation → surprise

On every `trust_observer` event for subject `s`:

```python
predicted = self.predict(subject_id=s)          # q_s(o_{t+1}) from last state
actual    = event_to_observation(evt)           # o_{t+1} realized
surprise  = self.compute_free_energy(predicted, actual)
# F ≈ KL(q_s(o) || p(o))
# Operationally: sum over the three factors of
# -log P_s(observed_syscall)  +  -log P_s(observed_band)  +  -log P_s(observed_metab)
self._free_energy_ema[s] = 0.95 * self._free_energy_ema.get(s, 0.0) + 0.05 * surprise
```

### 3c. Perception update (model learning)

If surprise is below threshold τ_perceive, just update the generative model
(standard online Bayesian count update, which `behavioral_markov` already
does). This is *perception*: "the world is slightly off my model, nudge the
model."

### 3d. Action selection (when surprise exceeds τ_act)

When `surprise > τ_act`, the cortex scores each candidate action `π ∈
{no_op, alert, restrict, escalate}` by its expected free energy `G(π)`:

```python
def expected_free_energy(self, subject_id, action):
    # Forward-simulate what would happen if we took `action`:
    predicted_o_given_action = self.simulate(subject_id, action, horizon=3)
    # Pragmatic value: does the action move the subject toward a preferred
    # distribution (our "prior preferences" -- STEADY_FLOW metabolic state,
    # USER or INTERACT band, benign syscall profile)?
    pragmatic = -self.kl(predicted_o_given_action, self.preferred_distribution)
    # Epistemic value: does the action resolve uncertainty about which
    # regime the subject is in? Measured as expected information gain.
    epistemic = self.expected_info_gain(subject_id, action)
    # G = -(pragmatic + epistemic) -- we MINIMIZE G, so higher pragmatic
    # and higher epistemic both lower G.
    return -(pragmatic + epistemic)

best_action = argmin_over(actions, self.expected_free_energy)
```

The **preferred distribution** encodes the system's "priors over the world
it wants to inhabit" — subjects in STEADY_FLOW with low syscall entropy and
stable band. This is the clean FEP formulation of "AI objective function"
— it lives in one place, in a dict, on-disk, editable [2, Ch. 6].

### 3e. Markov blanket respect

Critically, the cortex **does not read** the subject's internal state. It
reads only what is exposed across `/dev/trust` / `/sys/kernel/trust/*` —
the literal blanket. This is both (a) a security invariant (the cortex
cannot see token values, per Theorem 1 in the Roberts/Eli/Leelee paper) and
(b) the defining property of a Friston agent — that it *cannot see hidden
states directly, it can only infer them from the blanket* [7]. The two
constraints coincide, which is why the mapping is clean.

---

## 4. Pseudocode of the full loop

```python
# ai-control/cortex/active_inference.py
# ~400 LOC total including docstrings, thread-safety, tests.

from __future__ import annotations
import math
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple

from ..daemon.behavioral_markov import get_model as get_syscall_model
from ..daemon.trust_markov      import get_chain as get_band_chain
from .dynamic_hyperlation       import MarkovTransitionMatrix  # metabolic
from .autonomy                  import ActionEmitter

class ActiveInferenceCortex:
    """
    Minimum viable active-inference cortex.

    For each subject, maintains a factored generative model q(o) = q(syscall) *
    q(band) * q(metabolic), computes variational free energy per event against
    the realized observation, and when F_ema(s) > tau_act, emits the action
    that minimizes expected future free energy.

    This is the module S69 said was missing. It does NOT replace the existing
    Markov modules; it SUBSCRIBES to them and closes the action loop.
    """

    def __init__(self,
                 emitter: ActionEmitter,
                 tau_perceive: float = 1.5,   # nats; below = just update
                 tau_act:      float = 4.0,   # nats; above = choose action
                 ema_alpha:    float = 0.05,
                 horizon:      int   = 3):
        self._lock          = threading.Lock()
        self._emitter       = emitter
        self._tau_perceive  = tau_perceive
        self._tau_act       = tau_act
        self._alpha         = ema_alpha
        self._horizon       = horizon
        self._free_energy_ema: Dict[int, float] = defaultdict(float)
        self._last_obs:        Dict[int, Tuple] = {}
        self._preferred_dist  = self._default_preferred_distribution()

    def on_event(self, evt: "cortex.event_bus.Event") -> None:
        """Subscribe point: called by event_bus for every observer emission."""
        s = evt.subject_id
        o_actual = self._event_to_observation(evt)
        q_predicted = self._predict(s)
        F = self._variational_free_energy(q_predicted, o_actual)

        with self._lock:
            self._free_energy_ema[s] = ((1 - self._alpha) * self._free_energy_ema[s]
                                         + self._alpha * F)
            ema = self._free_energy_ema[s]
            self._last_obs[s] = o_actual

        if ema < self._tau_perceive:
            # Low surprise -- the world matches our model. Update model (perception).
            # (behavioral_markov / trust_markov already did this via their own
            # observe() calls; this branch is a no-op for us.)
            return

        if ema < self._tau_act:
            # Moderate surprise -- update faster, but don't act yet.
            # Same no-op; the producer-side modules learn from every event.
            return

        # High surprise -- act.
        action = self._choose_action(s)
        if action != "no_op":
            self._emitter.emit(subject_id=s, action=action,
                                 reason=f"F_ema={ema:.2f} > tau_act={self._tau_act}")

    # ---- Prediction ---------------------------------------------------------
    def _predict(self, s: int) -> Dict[str, Dict[str, float]]:
        syscall_model = get_syscall_model()
        band_chain    = get_band_chain(s)
        # metabolic_chain is per-subject in dynamic_hyperlation
        return {
            "syscall":   syscall_model.next_distribution_for(s),
            "band":      band_chain.next_band_distribution(),
            "metabolic": self._metabolic_prediction(s),
        }

    # ---- Free energy --------------------------------------------------------
    def _variational_free_energy(self,
                                 q_predicted: Dict[str, Dict[str, float]],
                                 o_actual: Tuple[str, str, str]) -> float:
        """
        Factored free energy: F = sum_k -log q_k(o_k).
        This is the cross-entropy part (accuracy term). A full F would also
        add KL[q(s)||p(s)] (complexity term); we approximate by assuming
        q(s) = q(o_t) directly, which is the standard mean-field cheap form.
        See Parr et al. 2022 Ch. 4.
        """
        syscall, band, metab = o_actual
        eps = 1e-6
        return (-math.log(q_predicted["syscall"  ].get(syscall, eps))
                - math.log(q_predicted["band"     ].get(band,    eps))
                - math.log(q_predicted["metabolic"].get(metab,   eps)))

    # ---- Action selection ---------------------------------------------------
    def _choose_action(self, s: int) -> str:
        candidates = ["no_op", "alert", "restrict", "escalate"]
        scores = {a: self._expected_free_energy(s, a) for a in candidates}
        return min(scores, key=scores.get)

    def _expected_free_energy(self, s: int, action: str) -> float:
        # Forward-simulate: what would o_{t+1..t+horizon} look like under this action?
        simulated = self._simulate(s, action, self._horizon)
        # Pragmatic: how close is simulated to preferred_dist?
        pragmatic = self._cross_entropy(simulated, self._preferred_dist)
        # Epistemic: how much uncertainty would this action resolve?
        epistemic = self._expected_info_gain(s, action)
        # G: lower is better. We want high pragmatic value (low cross-entropy)
        # AND high epistemic value (high info gain).
        return pragmatic - epistemic

    # ---- etc. Forward simulation, info gain, preferred-dist loading --------
    # ... remaining ~150 LOC ...
```

This is the full real loop. No hand-waving; it fits in 400 LOC because
every heavy-lifting piece is already a singleton in the repo.

---

## 5. Predictive coding and why the hierarchy matters

Friston's predictive-coding view [9] (Rao & Ballard 1999 [10] first, extended
by Friston 2005 [11] to variational form) maps perfectly to our 5-layer
architecture:

| Friston hierarchy | Our layer | What it predicts | Error signal direction |
| --- | --- | --- | --- |
| Sensory cortex (low) | Layer 0 — kernel | raw syscall / ioctl event | upward: "this wasn't expected" |
| Perceptual (mid) | Layer 2 — PE runtime | next DLL call, import, API | upward |
| Conceptual (high) | Layer 4 — cortex | band transition, verdict | upward: global surprise |
| Motor (executive) | Layer 4 action emit | intervention choice | downward: "constrain the subject" |

Predictions flow **down**, prediction errors flow **up**, actions flow
**down** — precisely the "commands flow down, events flow up, no layer
calls upward" invariant we already have in CLAUDE.md. The mapping is not
invented; it is observed.

Two implications:

1. **The architecture we have is already Fristonian.** We built it by
   thinking about cells, mitochondria, and RNA, and we ended up with
   something that is — formally — a hierarchical active-inference agent.
   This is not a coincidence; biological systems converge on this shape
   because of FEP itself.
2. **The "no upward calls" rule is the Markov-blanket invariant.** Upward
   calls would let internal states of a lower layer depend directly on
   internal states of a higher layer, violating the conditional-independence
   property that defines a blanket. The architectural rule we maintain for
   *engineering reasons* is mathematically the rule FEP requires for
   *inference reasons*.

---

## 6. Active inference for AI agents: state of the art (2022–2026)

The last four years have seen active inference move from neuroscience
theory to deployed AI. Three threads matter for us:

**Thread 1: deep active inference.** Tschantz, Millidge, Seth, Buckley
(2020–2023) [12, 13] showed that the FEP can be scaled by replacing
tabular `q(s)` with a neural network. Da Costa et al. 2023 [14] derived
a unified loss that reduces to maximum-likelihood learning on-policy and
to variational expectation maximization off-policy. This matters because
our `behavioral_markov` is already a count-based tabular approximation;
the path to a learned-embedding version is well-understood.

**Thread 2: active inference for control / robotics.** Lanillos, Oliver
(2021–2023) [15] and Sancaktar et al. (2023) [16] demonstrated active
inference driving physical robots with sensorimotor loops. Their core
insight — that action selection falls out of `min G(π)` without any
explicit reward — is exactly why FEP suits our use case. Our cortex has
no reward signal; it has a trust-ledger and a set of policy actions.
FEP gives a principled answer: minimize expected free energy against a
preferred-distribution prior.

**Thread 3: the MIT Press textbook.** Parr, Pezzulo, Friston 2022 [2] is
the first full-length modern synthesis. It shipped code (in MATLAB / SPM,
but the equations are the equations) for the full loop we are replicating.
Our Python implementation is the minimal translation of their Chapter 4
"Active Inference in Discrete-State-Space Models" into our event-driven
stack.

**Thread 4 (2024 onward): LLMs as generative models.** Friston et al. in
2024 [17] argued that LLMs can serve as the generative model in an FEP
agent, with prompt-context as the state and tokens as observations. Our
`llama-cpp-python` hook could be the generative model for higher-level
policy selection (verdict chains) while `behavioral_markov` remains the
low-level syscall model. This is a clean two-tier generative model —
Chapter 9 of Parr et al. [2].

---

## 7. Integration plan

### Step 1 (50 LOC): subscribe cortex to observer stream

Today `cortex/event_bus.py` has handler registration but cortex's
`DecisionMarkovModel` is never registered as a consumer. Add:

```python
# cortex/main.py (or wherever cortex starts up)
from .active_inference import ActiveInferenceCortex
from .event_bus import EventBus

aic = ActiveInferenceCortex(emitter=autonomy.emitter())
event_bus.register_handler(
    source_layers=[SourceLayer.KERNEL, SourceLayer.RUNTIME],
    callback=aic.on_event,
)
```

This closes the S69 gap in one registration call.

### Step 2 (200 LOC): implement `active_inference.py` core

The pseudocode in §4 is the target. Ship as a standalone module so the
existing `DecisionMarkovModel` continues to work (belt + suspenders) while
we validate free energy calibration on a real subject stream.

### Step 3 (100 LOC): preferred-distribution file + CLI

Add `/etc/ai-control/preferred_distribution.yaml` — the operator-editable
prior preferences (which bands / metabolic states / syscall patterns the
cortex should pull subjects toward). Add `ai cortex fep status` CLI showing
per-subject `F_ema` and current action scores.

### Step 4 (50 LOC): pytest

Three tests:
1. "Surprise detection" — inject an observation far off the model,
   assert `F > tau_act`, assert emitted action is non-no_op.
2. "Perception learning" — feed 100 consistent observations, assert
   model predictions improve and `F_ema` decays.
3. "Markov blanket respect" — assert cortex never reads token values
   or any `/sys/kernel/trust/*` path outside the published blanket.

### Step 5 (later): hierarchical extension

Once the flat `F` loop is stable, wire `DecisionMarkovModel` as the
top-of-hierarchy generative model consuming *aggregated* per-subject
surprise as its own sensory input. This is the two-level predictive
hierarchy from Friston 2005 [11] — and it is the honest justification
for the seven-Markov-chain architecture we ended up with.

---

## 8. What this changes about the repo's narrative

Today the docs framing is "we have eight Markov chains; they exist because
theorems 2/3/5/7 have Markov-chain interpretations." That's true, but it
is the *what*, not the *why*. After active inference lands, the narrative
upgrades to:

> ARCHWINDOWS's cortex implements a minimal active-inference agent.
> The eight Markov chains are the factored generative model; the free
> energy principle is the loss function; the trust kernel's `/dev/trust`
> blanket is the Markov blanket separating the agent from its environment.
> When a subject's behavior becomes predictable, the cortex updates its
> model. When behavior is surprising, the cortex acts. The action set
> (alert / restrict / escalate / apoptose) is chosen to minimize expected
> future surprise — not to maximize an external reward, because there is
> no external reward; the system is homeostatic, not reinforcement-learning.

This is a *significantly stronger* claim than "we have Markov chains." It
ties the design back to a 20-year body of published theory, provides
mathematical justification for architectural choices we made on biological
intuition, and gives the learning loop a name that reviewers will
recognize.

---

## 9. Failure modes and honest limitations

Three ways this can look good on paper and fail in practice:

1. **Prior / preferred-distribution mis-specification.** If the preferred
   distribution is wrong ("subjects should always be STEADY_FLOW, syscall
   entropy < 1.5 bits"), the cortex will act against healthy diversity.
   Mitigation: preferred distribution is a *mean + tolerance* (Gaussian-ish
   over a discrete simplex), not a delta. Operators tune tolerances; the
   cortex does not learn the preferred distribution from data (that would
   be homeostatic collapse, well-known failure mode [18]).
2. **Free energy miscalibration.** `tau_act` is a per-subject tuning
   knob; pick it too low and the cortex thrashes, too high and it never
   acts. Mitigation: start with `tau_act = P(F under healthy subject)` at
   99.5th percentile + continuous recalibration against a "known healthy"
   pool of subjects.
3. **Factored model is wrong.** Syscall × band × metabolic is independent
   in our model; empirically they are not. Mean-field approximations can
   get structurally bad. Mitigation: log factorization errors; revisit to
   a structured variational posterior (one of the obvious ML upgrades once
   the flat version is validated).

These are all **known** failure modes of FEP implementations — the
literature has explicit guidance [2, 14]. We will hit them; the point of
the active-inference framing is that we know *what* we'll hit and why.

---

## 10. The exploit, in one paragraph

Replace the bigram-counter `DecisionMarkovModel` with an
`ActiveInferenceCortex` (`ai-control/cortex/active_inference.py`, ~400 LOC)
that subscribes to `trust_observer` + `behavioral_markov` event streams,
maintains a per-subject factored generative model over (syscall × band ×
metabolic) distributions, computes variational free energy against each
realized observation, updates the model when `F < τ_perceive` (perception),
and when `F_ema > τ_act` emits the action minimizing expected future free
energy (action). Prior preferences live in an editable YAML; the full loop
respects `/dev/trust` as its Markov blanket, never reading subject-internal
state. This converts the cortex from a passive co-occurrence counter into
a principled Bayesian agent with explicit prediction error, explicit action
selection, and explicit homeostatic objective. Eight Markov chains stop
being "heuristics we glued on" and start being "factored generative model
of an active-inference agent." The implementation is a single new consumer
on an existing producer bus; no existing code has to move.

---

## 11. References

[1] Friston, K. (2006). *A free energy principle for the brain.* Journal of
Physiology (Paris), 100(1-3), 70-87.
<https://doi.org/10.1016/j.jphysparis.2006.10.001>

[2] **Parr, T., Pezzulo, G., Friston, K. (2022).** *Active Inference: The
Free Energy Principle in Mind, Brain, and Behavior.* MIT Press. (The
reference textbook.) ISBN 9780262045353.

[3] Friston, K., Kilner, J., Harrison, L. (2006). *A free energy principle
for the brain.* J. Physiol. Paris 100, 70–87.

[4] Friston, K. (2010). *The free-energy principle: a unified brain theory?*
Nature Reviews Neuroscience 11, 127–138.
<https://doi.org/10.1038/nrn2787>

[5] Friston, K., Rigoli, F., Ognibene, D., Mathys, C., FitzGerald, T.,
Pezzulo, G. (2015). *Active inference and epistemic value.* Cognitive
Neuroscience 6(4), 187–214.
<https://doi.org/10.1080/17588928.2015.1020053>

[6] Schwartenbeck, P., Passecker, J., Hauser, T. U., FitzGerald, T. H.,
Kronbichler, M., Friston, K. (2019). *Computational mechanisms of curiosity
and goal-directed exploration.* eLife 8:e41703.
<https://doi.org/10.7554/eLife.41703>

[7] Friston, K. (2013). *Life as we know it.* Journal of the Royal Society
Interface 10(86), 20130475.
<https://doi.org/10.1098/rsif.2013.0475>

[8] Friston, K., Da Costa, L., Hafner, D., Hesp, C., Parr, T. (2021).
*Sophisticated Inference.* Neural Computation 33(3), 713–763.
<https://doi.org/10.1162/neco_a_01351>

[9] Clark, A. (2013). *Whatever next? Predictive brains, situated agents,
and the future of cognitive science.* Behavioral and Brain Sciences 36(3),
181–204.

[10] Rao, R. P. N., Ballard, D. H. (1999). *Predictive coding in the visual
cortex: a functional interpretation of some extra-classical receptive-field
effects.* Nature Neuroscience 2, 79–87.

[11] Friston, K. (2005). *A theory of cortical responses.* Philosophical
Transactions of the Royal Society B 360(1456), 815–836.

[12] **Tschantz, A., Millidge, B., Seth, A. K., Buckley, C. L. (2023).**
*Hybrid predictive coding: Inferring, fast and slow.* PLOS Computational
Biology 19(8): e1011280.
<https://doi.org/10.1371/journal.pcbi.1011280>

[13] Millidge, B., Tschantz, A., Buckley, C. L. (2021). *On the relationship
between active inference and control as inference.* Proc. IWAI 2021.

[14] **Da Costa, L., Parr, T., Sajid, N., Veselic, S., Neacsu, V., Friston,
K. (2023).** *Active inference on discrete state-spaces: A synthesis.*
Journal of Mathematical Psychology 99, 102447.
<https://doi.org/10.1016/j.jmp.2020.102447>

[15] **Lanillos, P., Oliver, G. (2021).** *Active inference body perception
and action for humanoid robots.* arXiv:2106.03924.

[16] **Sancaktar, C., van Gerven, M. A. J., Lanillos, P. (2020).** *End-to-end
pixel-based deep active inference for body perception and action.* In Proc.
ICDL 2020.

[17] **Friston, K. et al. (2024).** *Designing ecosystems of intelligence
from first principles.* Collective Intelligence 3(2).
<https://doi.org/10.1177/26339137231222481>

[18] Sajid, N., Ball, P. J., Parr, T., Friston, K. (2021). *Active inference:
demystified and compared.* Neural Computation 33(3), 674–712.
<https://doi.org/10.1162/neco_a_01357>

[19] Hohwy, J. (2013). *The Predictive Mind.* Oxford University Press.
(For the Markov-blanket philosophy-of-mind framing.)

[20] Hafner, D., Ortega, P. A., Ba, J., Parr, T., Friston, K., Heess, N.
(2022). *Action and perception as divergence minimization.*
arXiv:2009.01791v5.

---

## 12. Appendix A: the minimal free-energy derivation

For completeness, here is the three-line derivation of why minimizing `F`
minimizes surprise. Given observation `o` and hidden state `s`:

```
surprise(o) = -log p(o)
            = -log ∫ p(o, s) ds                           (marginalize)
            = -log ∫ q(s) · (p(o, s) / q(s)) ds           (importance)
            ≤ -∫ q(s) log (p(o, s) / q(s)) ds             (Jensen's)
            = E_q[log q(s) - log p(o, s)]
            = F                                            (variational FE)
```

So `F ≥ surprise`. Minimizing `F` drives an upper bound on surprise
downward. Everything else in active inference unfolds from this one
inequality [2, §2.3; 4]. This is why the name — it is literally the
Helmholtz free energy from statistical physics, rearranged for brains.

---

## 13. Appendix B: one-day proof-of-concept script

Before writing the full module, run this against the live daemon to
validate that `trust_observer` actually emits useful signal:

```python
# scripts/fep_probe.py (~60 LOC)
# Subscribes to trust_observer events for 60 seconds, computes surprise
# against behavioral_markov predictions, prints histogram.
# If the histogram is degenerate (all-zero surprise or all-infinity),
# the active-inference plan is blocked until the producers are fixed.
```

Ship this first. If the histogram looks sane (fat tail, median in single
digits of nats), proceed to `active_inference.py`. If not, file the
producer bug instead of building on a broken foundation.
