"""
Monte-Carlo Cortex -- S74 Agent T  (Research A gap #2, Von Neumann beyond canon).

von Neumann co-invented the Monte Carlo method with Stanisław Ulam at Los Alamos
(1946-47).  His 1949 paper ("Various techniques used in connection with random
digits", in Monte Carlo Methods, National Bureau of Standards series) is one of
the founding documents of stochastic simulation.  A module named `cortex` that
already ships a Markov chain (decision_engine.py), a deterministic derivative
loop (dynamic_hyperlation.py), and a variational-Bayes agent (active_inference.py)
but has *no* stochastic-sampling layer was the single largest methodological
gap Research A flagged against the Von-Neumann canon.

This module closes that gap with three complementary estimators and a thin
uncertainty-quantification wrapper the cortex veto logic can consume:

  1. MonteCarloSampler.sample_posterior   -- rejection sampling
  2. MonteCarloSampler.estimate_expectation -- importance sampling
  3. MonteCarloSampler.mcmc_chain         -- Metropolis-Hastings
  4. UncertaintyQuantifier.quantify       -- (mean, std, p05, p95) CI for
                                             a decision_fn over noisy inputs.

Design constraints
------------------
* Zero deps beyond Python 3 stdlib (random, math, statistics, collections).
* Thread-safe: one RLock per sampler instance; RNG access is serialised.
* Default n=1000 completes well under 100 ms on commodity hardware.
* Degenerate-sample case (too few / all-nan outputs) returns math.nan rather
  than raising -- cortex veto code treats nan as "defer / escalate", which is
  the intended uncertainty response.

Skeleton scope (S74)
--------------------
Functional but deliberately light on numerical-stability polish: no log-sum-exp,
no adaptive proposal, no parallel-chain R-hat, no reversible-jump.  Those live
in S75 alongside FEP coupling and cortex veto wire-up.  What ships now: correct
basic math, the public API active_inference / entropy_observer / assembly_index
use, an HTTP + event-bus integration following Agent N's audit convention.

References
----------
* Metropolis N, Ulam S. "The Monte Carlo Method." J. Am. Stat. Assoc. 44 (1949).
* Hastings WK. "Monte Carlo sampling methods using Markov chains and their
  applications." Biometrika 57 (1970).
* Kahn H, Marshall AW. "Methods of reducing sample size in Monte Carlo
  computations." J. Operations Research 1 (1953) -- importance sampling.
"""

from __future__ import annotations

import logging
import math
import random
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

logger = logging.getLogger("cortex.monte_carlo")

# --------------------------------------------------------------------------
# Design constants
# --------------------------------------------------------------------------

# Default draw count.  Chosen so that a single quantify() call completes in
# well under 100 ms even when the supplied decision_fn is a few microseconds
# of Python.  Power-of-ten for easy reasoning about standard errors.
DEFAULT_N = 1000

# Rejection-sampling safety ceiling.  Without this, pathological likelihoods
# could spin forever.  If the sampler hasn't accepted the requested number of
# samples after REJECTION_MAX_MULTIPLIER * n proposals, it returns what it
# has and logs a warning -- cortex treats a short sample set as "uncertain".
REJECTION_MAX_MULTIPLIER = 100

# MCMC burn-in default.  Sufficient for well-mixing symmetric proposals on
# simple targets; cortex callers that need more should pass n_burn explicitly.
DEFAULT_N_BURN = 100

# "Too few samples for meaningful stats" floor.  Below this we emit nan and a
# debug log rather than a confidence interval that would mislead the caller.
MIN_VALID_SAMPLES = 8


# --------------------------------------------------------------------------
# Core sampler
# --------------------------------------------------------------------------

class MonteCarloSampler:
    """
    Self-contained stochastic estimator.  One instance per logical use-site
    (e.g. one for UQ on trust-decision inputs, another for cortex policy
    roll-outs in S75).  Safe to call from executor threads; all RNG accesses
    are serialised through a per-instance RLock.

    Parameters
    ----------
    n_samples : int
        Default draw count when callers omit ``n``.
    seed : int | None
        If ``None`` use ``random.SystemRandom`` (cryptographic quality, good
        for production cortex where determinism is undesirable).  If an int
        is supplied, use a standard ``random.Random(seed)`` for reproducible
        unit tests.
    """

    def __init__(self, n_samples: int = DEFAULT_N,
                 seed: Optional[int] = None) -> None:
        self.n_samples = int(n_samples)
        self.seed = seed
        if seed is None:
            self._rng: random.Random = random.SystemRandom()
            self._deterministic = False
        else:
            self._rng = random.Random(int(seed))
            self._deterministic = True
        self._lock = threading.RLock()
        # lightweight telemetry ring for /metrics exposure
        self._draws_total: int = 0
        self._recent_expectations: deque[float] = deque(maxlen=32)
        self._active_chains: int = 0

    # ---- rejection sampling -----------------------------------------------

    def sample_posterior(self,
                         prior: dict[str, Any],
                         likelihood_fn: Callable[[float], float],
                         n: Optional[int] = None) -> dict[str, Any]:
        """
        Draw ``n`` posterior samples from a 1-D uniform prior via rejection.

        The ``prior`` dict must supply ``low`` and ``high`` (prior is assumed
        uniform on [low, high] -- a common case for cortex inputs bucketed
        into bounded ranges).  ``likelihood_fn(x)`` returns a non-negative
        weight; the envelope constant M is estimated online as the running
        max, which is correct in the limit (standard accept-reject with a
        progressively tightening upper bound).

        Returns
        -------
        {
          "samples":       list[float],
          "mean":          float | nan,
          "accepted":      int,
          "proposed":      int,
          "acceptance":    float,          # accepted / proposed
        }
        """
        n = int(n if n is not None else self.n_samples)
        low = float(prior.get("low", 0.0))
        high = float(prior.get("high", 1.0))
        if high <= low:
            raise ValueError(f"prior bounds must satisfy low < high (got {low}, {high})")

        accepted: list[float] = []
        proposed = 0
        envelope_m = 0.0
        max_proposals = REJECTION_MAX_MULTIPLIER * n

        with self._lock:
            while len(accepted) < n and proposed < max_proposals:
                x = self._rng.uniform(low, high)
                w = float(likelihood_fn(x))
                proposed += 1
                if w > envelope_m:
                    envelope_m = w
                if envelope_m <= 0.0:
                    continue
                if self._rng.random() < w / envelope_m:
                    accepted.append(x)
            self._draws_total += proposed

        if proposed >= max_proposals and len(accepted) < n:
            logger.warning("rejection sampler hit proposal ceiling: accepted=%d / n=%d",
                           len(accepted), n)

        mean = statistics.fmean(accepted) if len(accepted) >= MIN_VALID_SAMPLES else math.nan
        return {
            "samples": accepted,
            "mean": mean,
            "accepted": len(accepted),
            "proposed": proposed,
            "acceptance": (len(accepted) / proposed) if proposed else 0.0,
        }

    # ---- importance sampling ----------------------------------------------

    def estimate_expectation(self,
                             f: Callable[[float], float],
                             proposal_dist: Callable[[random.Random], float],
                             n: Optional[int] = None,
                             weight_fn: Optional[Callable[[float], float]] = None) -> float:
        """
        Estimate E_p[f(X)] via importance sampling.

        ``proposal_dist(rng)`` must return a single draw from some proposal q.
        ``weight_fn(x)`` returns the likelihood ratio p(x)/q(x); when omitted
        we assume the proposal *is* the target (vanilla Monte Carlo mean),
        which is the common case for cortex inputs where we already know the
        distribution and just want E[f].
        """
        n = int(n if n is not None else self.n_samples)
        total = 0.0
        total_w = 0.0
        count = 0
        with self._lock:
            for _ in range(n):
                x = proposal_dist(self._rng)
                w = 1.0 if weight_fn is None else float(weight_fn(x))
                try:
                    fx = float(f(x))
                except Exception:
                    continue
                if not math.isfinite(fx):
                    continue
                total += w * fx
                total_w += w
                count += 1
            self._draws_total += n

        if count < MIN_VALID_SAMPLES or total_w <= 0.0:
            logger.debug("importance sampling degenerate: count=%d, total_w=%.3e",
                         count, total_w)
            return math.nan
        est = total / total_w
        self._recent_expectations.append(est)
        return est

    # ---- Metropolis-Hastings ----------------------------------------------

    def mcmc_chain(self,
                   initial: float,
                   transition: Callable[[float, random.Random], float],
                   target_log_density: Callable[[float], float],
                   n_burn: int = DEFAULT_N_BURN,
                   n: Optional[int] = None) -> list[float]:
        """
        Draw an M-H chain of length ``n`` (after discarding ``n_burn``).

        ``transition(x, rng)`` is a *symmetric* proposal q(x' | x).  Symmetry
        lets us use the classical Metropolis acceptance ratio
        min(1, exp(log pi(x') - log pi(x))) without a Hastings correction;
        for asymmetric proposals callers should embed the correction inside
        ``target_log_density``.

        Returns the post-burn-in sample list.  NaN log-densities are treated
        as -inf (rejected); exceptions in proposal or target are silenced
        and treated as rejection.
        """
        n = int(n if n is not None else self.n_samples)
        n_burn = int(n_burn)
        x = float(initial)
        try:
            log_pi = float(target_log_density(x))
        except Exception:
            log_pi = -math.inf
        if not math.isfinite(log_pi):
            log_pi = -math.inf

        samples: list[float] = []
        with self._lock:
            self._active_chains += 1
            try:
                for i in range(n_burn + n):
                    try:
                        x_prop = float(transition(x, self._rng))
                        log_pi_prop = float(target_log_density(x_prop))
                    except Exception:
                        log_pi_prop = -math.inf
                    if not math.isfinite(log_pi_prop):
                        log_pi_prop = -math.inf
                    delta = log_pi_prop - log_pi
                    if delta >= 0.0 or self._rng.random() < math.exp(delta):
                        x, log_pi = x_prop, log_pi_prop
                    if i >= n_burn:
                        samples.append(x)
                self._draws_total += n_burn + n
            finally:
                self._active_chains -= 1
        return samples

    # ---- introspection ----------------------------------------------------

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "n_samples_default": self.n_samples,
                "deterministic": self._deterministic,
                "draws_total": self._draws_total,
                "active_chains": self._active_chains,
                "recent_expectations": list(self._recent_expectations),
            }


# --------------------------------------------------------------------------
# UncertaintyQuantifier  --  public cortex-veto-facing surface
# --------------------------------------------------------------------------

@dataclass
class UncertaintyResult:
    mean: float
    std: float
    p05: float
    p95: float
    n_valid: int
    elapsed_s: float = 0.0

    def as_tuple(self) -> tuple[float, float, float, float]:
        """Contract return as specified in the agent brief."""
        return (self.mean, self.std, self.p05, self.p95)

    def uncertain(self, threshold: float) -> bool:
        """True if p95 - p05 exceeds the calling site's tolerance."""
        if not math.isfinite(self.p05) or not math.isfinite(self.p95):
            return True
        return (self.p95 - self.p05) > threshold


class UncertaintyQuantifier:
    """
    Wrap a MonteCarloSampler with the uncertainty-CI contract the cortex veto
    logic consumes in S75.  A decision_fn that maps noisy inputs to a scalar
    score is evaluated on n samples drawn from input_distribution; we return
    (mean, std, p05, p95) so callers can gate on the width of the 90 % CI.

    Typical use (S75 wire-up):

        uq = UncertaintyQuantifier()
        mean, std, p05, p95 = uq.quantify(
            decision_fn=lambda state: trust_policy_score(state),
            input_distribution=noisy_state_sampler,
            n_samples=1000,
        ).as_tuple()
        if p95 - p05 > 0.2:
            escalate_to_algedonic()   # too uncertain -> defer
    """

    def __init__(self, sampler: Optional[MonteCarloSampler] = None,
                 seed: Optional[int] = None) -> None:
        self.sampler = sampler or MonteCarloSampler(seed=seed)
        self._lock = threading.RLock()
        self._last_result: Optional[UncertaintyResult] = None
        self._history: deque[UncertaintyResult] = deque(maxlen=64)

    def quantify(self,
                 decision_fn: Callable[[Any], float],
                 input_distribution: Callable[[random.Random], Any],
                 n_samples: Optional[int] = None) -> UncertaintyResult:
        """
        Apply ``decision_fn`` to ``n_samples`` draws from ``input_distribution``
        and return the resulting summary statistics.

        Graceful degradation: non-finite or exception-raising evaluations are
        dropped; if fewer than MIN_VALID_SAMPLES survive, every statistic is
        NaN and a warning log is emitted.
        """
        n = int(n_samples if n_samples is not None else self.sampler.n_samples)
        outputs: list[float] = []
        t0 = time.perf_counter()

        with self.sampler._lock:   # borrow the sampler's lock for RNG draws
            for _ in range(n):
                try:
                    x = input_distribution(self.sampler._rng)
                    y = float(decision_fn(x))
                except Exception:
                    continue
                if math.isfinite(y):
                    outputs.append(y)
            self.sampler._draws_total += n

        elapsed = time.perf_counter() - t0
        if len(outputs) < MIN_VALID_SAMPLES:
            logger.warning("quantify: only %d/%d valid samples -> nan CI",
                           len(outputs), n)
            res = UncertaintyResult(math.nan, math.nan, math.nan, math.nan,
                                    n_valid=len(outputs), elapsed_s=elapsed)
        else:
            outputs.sort()
            mean = statistics.fmean(outputs)
            std = statistics.pstdev(outputs) if len(outputs) >= 2 else 0.0
            # Percentile via nearest-rank -- no scipy dep; sufficient for
            # cortex-gate granularity (sub-percent is noise anyway).
            k05 = max(0, min(len(outputs) - 1, int(round(0.05 * (len(outputs) - 1)))))
            k95 = max(0, min(len(outputs) - 1, int(round(0.95 * (len(outputs) - 1)))))
            res = UncertaintyResult(mean, std, outputs[k05], outputs[k95],
                                    n_valid=len(outputs), elapsed_s=elapsed)

        with self._lock:
            self._last_result = res
            self._history.append(res)
        return res

    # ---- metrics ----------------------------------------------------------

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            last = self._last_result
            history = list(self._history)
        return {
            "last": (None if last is None else {
                "mean": last.mean,
                "std": last.std,
                "p05": last.p05,
                "p95": last.p95,
                "n_valid": last.n_valid,
                "elapsed_s": last.elapsed_s,
            }),
            "n_history": len(history),
            "sampler": self.sampler.stats(),
        }


# --------------------------------------------------------------------------
# Daemon wiring  --  mirrors active_inference / entropy_observer / assembly
# --------------------------------------------------------------------------

_quantifier: Optional[UncertaintyQuantifier] = None


def _builtin_reward_fn(profile: str) -> Callable[[str, random.Random], float]:
    """Named reward profiles for the /cortex/monte_carlo/rollout endpoint.

    Reward profiles:
      * "uniform"    -- uniform(0, 1). Neutral baseline; best_action is
                        whichever action got lucky rolls.
      * "prefer_noop" -- strongly rewards the literal "noop" action;
                         everything else N(0, 1). Smoke-test the
                         "known-good action wins" path.
      * "deny_biased" -- penalises "deny" by subtracting 1.0 from its
                         mean. Smoke-test the "known-bad action loses" path.
    """
    name = str(profile or "uniform").lower()
    if name == "prefer_noop":
        def _r(action: str, rng: random.Random) -> float:
            base = rng.gauss(0.0, 1.0)
            return base + (2.0 if action == "noop" else 0.0)
        return _r
    if name == "deny_biased":
        def _r(action: str, rng: random.Random) -> float:
            base = rng.gauss(0.0, 1.0)
            return base - (1.0 if action == "deny" else 0.0)
        return _r
    # Default
    return lambda action, rng: rng.random()


def _run_rollout_endpoint(body: Any, samplers: dict[str, Any]) -> dict[str, Any]:
    """Pure-python body of POST /cortex/monte_carlo/rollout.

    Extracted so the handler can be unit-tested without a FastAPI
    dependency. Accepts a dict-like body with keys ``actions``,
    ``n_rollouts``, ``reward_profile``.
    """
    body = body if isinstance(body, dict) else {}
    actions = body.get("actions")
    if not isinstance(actions, list) or not actions:
        actions = ["noop", "allow", "deny", "escalate"]
    # Sanitise: cast each action to str.
    actions = [str(a) for a in actions]
    n_rollouts = body.get("n_rollouts")
    try:
        n_rollouts = int(n_rollouts) if n_rollouts is not None else None
    except Exception:
        n_rollouts = None
    profile = str(body.get("reward_profile", "uniform")).lower()
    rs = samplers.get("rollout_search") if isinstance(samplers, dict) else None
    if rs is None:
        return {"error": "rollout_search unavailable"}
    rec = rs.recommend(actions, _builtin_reward_fn(profile),
                       n_rollouts=n_rollouts)
    rec["profile"] = profile
    return rec


def get_quantifier() -> Optional[UncertaintyQuantifier]:
    """Return the process-wide UncertaintyQuantifier, if one was registered."""
    return _quantifier


def register_with_daemon(app: Any, event_bus: Any = None,
                         quantifier: Optional[UncertaintyQuantifier] = None
                         ) -> UncertaintyQuantifier:
    """
    Wire the Monte-Carlo layer into the FastAPI daemon + optional event bus.

    Follows the convention Agent N audited across active_inference,
    entropy_observer, and assembly_index:

      * Register ``GET /metrics/monte_carlo`` returning sampler + UQ metrics.
      * If ``event_bus`` is supplied and exposes any of ``subscribe``, ``on``,
        or ``add_callback``, subscribe to topic ``cortex.uncertainty.request``
        and publish results to ``cortex.uncertainty.result``.
      * All I/O is best-effort -- unit tests that pass stub apps or ``None``
        event_bus must not crash.

    Parameters
    ----------
    app : FastAPI | None
        The daemon's FastAPI instance.  May be ``None`` in unit tests.
    event_bus : EventBus | None
        Any object exposing publish / subscribe semantics, or ``None``.
    quantifier : UncertaintyQuantifier | None
        Inject an existing instance (tests); otherwise a fresh one is built.

    Returns
    -------
    UncertaintyQuantifier
        The live quantifier.  Caller keeps the reference so lifespan shutdown
        can reach it.
    """
    global _quantifier
    uq = quantifier if quantifier is not None else UncertaintyQuantifier()
    _quantifier = uq

    # Install process-wide samplers (S75 Agent C).  Done here so the four
    # auxiliary samplers share a single MonteCarloSampler (one RNG -> one
    # seed pins everything) and so callers like the decision engine can
    # fetch them via the get_confidence_sampler / get_rollout_search
    # helpers without knowing about the daemon boot order.
    samplers = register_samplers(seed=None)

    # ---- HTTP metric endpoint  (best-effort) ------------------------------
    if app is not None:
        try:
            @app.get("/metrics/monte_carlo")
            async def _mc_metrics():   # type: ignore[unused-ignore]
                out = uq.metrics()
                # Surface sampler stats so operators can see token-bucket
                # + fault-injection telemetry at a glance.
                fi = samplers["fault_injector"]
                rl = samplers["rate_limiter"]
                out["fault_injector"] = fi.stats() if fi else None
                out["rate_limiter"] = rl.stats() if rl else None
                return out
        except AttributeError:
            # Not a FastAPI app (unit-test stub).  Silently skip.
            logger.debug("register_with_daemon: app lacks .get; skipping HTTP route")
        except Exception:
            logger.debug("HTTP route registration failed", exc_info=True)

    # ---- Rollout POST endpoint  (S75 roadmap §1.2.4) ----------------------
    # Contract: POST /cortex/monte_carlo/rollout with JSON
    #   {
    #     "actions":        ["noop", "tighten_thresholds", ...],
    #     "n_rollouts":     64,          # optional, default sampler.n_rollouts
    #     "reward_profile": "uniform"     # optional; see _builtin_reward
    #   }
    # Returns: {"best_action": "...", "ranked": [{"action", "reward_mean",
    #          "reward_std", "n_rollouts", "probability"}, ...]}
    #
    # Because reward functions cannot cross an HTTP boundary as live
    # callables, the endpoint supports a small set of named built-in
    # reward profiles. Callers inside the Python process that need custom
    # reward_fn use RolloutSearch.recommend() directly.
    if app is not None:
        try:
            # Import lazily so pure-stdlib unit tests that load this module
            # outside a FastAPI context do not pay the import cost.
            try:
                from fastapi import Body as _Body   # type: ignore
            except Exception:
                _Body = None    # type: ignore

            if _Body is not None:
                @app.post("/cortex/monte_carlo/rollout")
                async def _mc_rollout(body: dict = _Body(default={})):   # type: ignore[unused-ignore]
                    return _run_rollout_endpoint(body, samplers)
            else:
                @app.post("/cortex/monte_carlo/rollout")
                async def _mc_rollout(body: dict):   # type: ignore[unused-ignore]
                    return _run_rollout_endpoint(body, samplers)
        except AttributeError:
            logger.debug("register_with_daemon: app lacks .post; skipping rollout route")
        except Exception:
            logger.debug("rollout route registration failed", exc_info=True)

    # ---- Event-bus wiring  (best-effort) ----------------------------------
    if event_bus is None:
        logger.info("monte_carlo registered (no event_bus)")
        return uq

    def _on_request(event: Any) -> None:
        """
        Handle a cortex.uncertainty.request event.  Payload (dict-like) may
        carry a callable ``decision_fn`` / ``input_distribution`` and an
        optional ``n_samples``; missing or non-callable fields cause a
        debug-logged soft skip.
        """
        try:
            payload = event.get("payload") if isinstance(event, dict) else None
            if not isinstance(payload, dict):
                return
            decision_fn = payload.get("decision_fn")
            input_dist = payload.get("input_distribution")
            if not callable(decision_fn) or not callable(input_dist):
                return
            n = payload.get("n_samples")
            res = uq.quantify(decision_fn, input_dist, n)
            _publish({
                "type": "cortex.uncertainty.result",
                "request_id": payload.get("request_id"),
                "mean": res.mean,
                "std": res.std,
                "p05": res.p05,
                "p95": res.p95,
                "n_valid": res.n_valid,
                "elapsed_s": res.elapsed_s,
                "ts": time.time(),
            })
        except Exception:
            logger.exception("cortex.uncertainty.request handler failed")

    def _publish(event: dict) -> None:
        for name in ("publish", "emit"):
            fn = getattr(event_bus, name, None)
            if callable(fn):
                try:
                    fn(event)
                    return
                except Exception:
                    logger.debug("event_bus.%s failed", name)
        logger.debug("uncertainty result (no bus sink): %s", event)

    subscribed = False
    for attr in ("subscribe", "on", "add_callback"):
        fn = getattr(event_bus, attr, None)
        if callable(fn):
            try:
                # Two common signatures: subscribe(topic, cb) / add_callback(cb)
                try:
                    fn("cortex.uncertainty.request", _on_request)
                except TypeError:
                    fn(_on_request)
                subscribed = True
                break
            except Exception:
                logger.debug("event_bus.%s subscribe failed", attr)

    if not subscribed:
        logger.debug("monte_carlo: event_bus has no compatible subscribe method")

    logger.info("monte_carlo registered (event_bus=%s, subscribed=%s)",
                type(event_bus).__name__, subscribed)
    return uq


# --------------------------------------------------------------------------
# S75 Agent C extensions -- roadmap §1.2.4 required sampler classes.
#
# Research-A §2.6 called out four specific deterministic sites in the cortex
# where stochasticity is methodologically absent:
#
#   1. confidence calibration                -> ConfidenceSampler
#   2. rollout search / action lookahead      -> RolloutSearch
#   3. fault injection / chaos probes         -> FaultInjector
#   4. token-pool replenishment rate limiter  -> StochasticRateLimiter
#
# These four classes are thin compositions over MonteCarloSampler so that the
# S74 skeleton remains the single source of truth for RNG seeding + locking.
# Each class:
#
#   * Accepts either an injected MonteCarloSampler (shared RNG) or creates
#     its own (independent RNG).
#   * Takes an optional ``seed`` kwarg for deterministic unit tests; when
#     ``seed`` is passed the behavior is reproducible bit-for-bit.
#   * Exposes a ``.sampler`` attribute so callers can introspect RNG state,
#     count draws through ``.sampler.stats()``, or share the RNG across
#     cooperating samplers (e.g. ConfidenceSampler + RolloutSearch sharing
#     one RNG so a single ``seed=42`` pins both).
#
# The classes do NOT replace MonteCarloSampler / UncertaintyQuantifier; they
# sit on top and express domain-specific contracts (beta posteriors, action
# rollouts, Bernoulli gates, token buckets) the cortex call-sites expect.
# --------------------------------------------------------------------------


class ConfidenceSampler:
    """
    Sample from a beta posterior over decision confidence.

    The decision engine currently emits a deterministic ``confidence: float``
    per EvalResult. ConfidenceSampler lets callers draw a calibrated sample
    from ``Beta(alpha, beta)`` where ``alpha = successes + 1`` and ``beta =
    failures + 1`` (Laplace smoother) or from an arbitrary ``(alpha, beta)``
    the caller supplies directly -- matches the S75 roadmap requirement
    "sampled confidence distribution matches input beta posterior within 2%
    over N=10000 samples" (docs/s75_roadmap.md §5 Item 4).

    Deterministic contract
    ----------------------
    When seeded with ``seed=int``, two instances produce the same samples in
    the same order. When ``deterministic_mean=True``, ``sample()`` returns
    ``alpha / (alpha + beta)`` (the posterior mean) -- the "seed path" the
    decision engine uses when it wants identical behaviour to the pre-MC
    deterministic confidence.
    """

    def __init__(self,
                 sampler: Optional[MonteCarloSampler] = None,
                 seed: Optional[int] = None,
                 deterministic_mean: bool = False) -> None:
        self.sampler = sampler or MonteCarloSampler(seed=seed)
        self.deterministic_mean = bool(deterministic_mean)

    def sample(self, alpha: float, beta: float,
               n: Optional[int] = None) -> float:
        """Return a single draw from Beta(alpha, beta).

        If ``deterministic_mean`` is True, return alpha/(alpha+beta) -- the
        posterior mean -- so the engine's behaviour is unchanged when the
        MC path is toggled off. ``n`` is accepted for API symmetry but only
        matters in ``sample_many``.
        """
        a = float(max(alpha, 1e-9))
        b = float(max(beta, 1e-9))
        if self.deterministic_mean:
            return a / (a + b)
        with self.sampler._lock:
            self.sampler._draws_total += 1
            # random.Random.betavariate handles a, b > 0 robustly.
            return float(self.sampler._rng.betavariate(a, b))

    def sample_many(self, alpha: float, beta: float,
                    n: Optional[int] = None) -> list[float]:
        """Draw ``n`` samples. Default n = sampler.n_samples."""
        count = int(n if n is not None else self.sampler.n_samples)
        a = float(max(alpha, 1e-9))
        b = float(max(beta, 1e-9))
        out: list[float] = []
        with self.sampler._lock:
            for _ in range(count):
                out.append(float(self.sampler._rng.betavariate(a, b)))
            self.sampler._draws_total += count
        return out

    def calibrated(self, base_confidence: float,
                   successes: int = 0, failures: int = 0) -> float:
        """Calibrate a deterministic confidence with prior counts.

        Useful when the decision engine has a base confidence but also an
        online success/failure tally; this returns a single beta draw with
        ``alpha = 1 + successes + base_confidence * k`` and
        ``beta  = 1 + failures  + (1 - base_confidence) * k`` using k=10 as
        a soft strength. In deterministic mode, returns the mean.
        """
        k = 10.0
        base = max(0.0, min(1.0, float(base_confidence)))
        a = 1.0 + successes + base * k
        b = 1.0 + failures + (1.0 - base) * k
        return self.sample(a, b)


@dataclass
class RolloutResult:
    """Result of a single rollout branch."""
    action: str
    reward_mean: float
    reward_std: float
    n_rollouts: int


class RolloutSearch:
    """
    Monte-Carlo rollout over a discrete action set.

    For each candidate action a in ``actions``, draw ``n_rollouts`` samples
    from ``reward_fn(action, rng)`` and report mean + stdev. Return the
    ranked list of RolloutResult so callers can take argmax or sample
    softmax.

    This is the methodological closure of research-A §2.6's point that the
    cortex "has a Markov chain ... but no stochastic sampling layer" --
    action lookahead in decision_engine is currently deterministic (policy
    rules + heuristic windows); RolloutSearch is the seam where stochastic
    outcome-prediction slots in.
    """

    def __init__(self,
                 sampler: Optional[MonteCarloSampler] = None,
                 seed: Optional[int] = None,
                 n_rollouts: int = 64) -> None:
        self.sampler = sampler or MonteCarloSampler(seed=seed)
        self.n_rollouts = int(n_rollouts)

    def search(self,
               actions: Iterable[str],
               reward_fn: Callable[[str, random.Random], float],
               n_rollouts: Optional[int] = None
               ) -> list[RolloutResult]:
        """Return list of RolloutResult sorted by descending ``reward_mean``.

        ``reward_fn(action, rng)`` must return a finite float reward for the
        supplied action using the supplied ``random.Random``. Non-finite /
        exception-raising evaluations are silently dropped; if a branch has
        fewer than MIN_VALID_SAMPLES valid rollouts its reward_mean is nan.
        """
        n = int(n_rollouts if n_rollouts is not None else self.n_rollouts)
        results: list[RolloutResult] = []
        with self.sampler._lock:
            for a in actions:
                rewards: list[float] = []
                for _ in range(n):
                    try:
                        r = float(reward_fn(a, self.sampler._rng))
                    except Exception:
                        continue
                    if math.isfinite(r):
                        rewards.append(r)
                self.sampler._draws_total += n
                if len(rewards) < MIN_VALID_SAMPLES:
                    results.append(RolloutResult(
                        action=str(a),
                        reward_mean=math.nan,
                        reward_std=math.nan,
                        n_rollouts=len(rewards),
                    ))
                else:
                    rm = statistics.fmean(rewards)
                    rs = statistics.pstdev(rewards) if len(rewards) >= 2 else 0.0
                    results.append(RolloutResult(
                        action=str(a),
                        reward_mean=rm,
                        reward_std=rs,
                        n_rollouts=len(rewards),
                    ))
        # NaN means sort to the back (treat as -inf for ranking).
        def _key(r: RolloutResult) -> float:
            return -math.inf if not math.isfinite(r.reward_mean) else r.reward_mean
        results.sort(key=_key, reverse=True)
        return results

    def recommend(self,
                  actions: Iterable[str],
                  reward_fn: Callable[[str, random.Random], float],
                  n_rollouts: Optional[int] = None
                  ) -> dict[str, Any]:
        """API-shaped recommendation dict for /cortex/monte_carlo/rollout."""
        ranked = self.search(actions, reward_fn, n_rollouts)
        # Softmax probabilities over reward_mean for ranking stability.
        valid = [r for r in ranked if math.isfinite(r.reward_mean)]
        if not valid:
            probs = {r.action: 0.0 for r in ranked}
            best: Optional[str] = None
        else:
            # Temperature 1.0 softmax; clip extremes for numerical stability.
            m = max(r.reward_mean for r in valid)
            exps = {r.action: math.exp(min(50.0, r.reward_mean - m))
                    for r in valid}
            z = sum(exps.values()) or 1.0
            probs = {a: v / z for a, v in exps.items()}
            for r in ranked:
                probs.setdefault(r.action, 0.0)
            best = valid[0].action
        return {
            "best_action": best,
            "ranked": [
                {
                    "action": r.action,
                    "reward_mean": r.reward_mean,
                    "reward_std": r.reward_std,
                    "n_rollouts": r.n_rollouts,
                    "probability": probs.get(r.action, 0.0),
                }
                for r in ranked
            ],
        }


class FaultInjector:
    """
    Stochastic fault gate for chaos-testing probes.

    ``should_fire(probability=p)`` returns True with probability p, sampled
    from a uniform draw. Used to gate fault-injection call-sites in safe
    mode without hard-coding a schedule. A chi-square sanity test at
    p>=0.05 should accept the null hypothesis that observed fires match the
    Bernoulli(p) expectation (docs/s75_roadmap.md §5 Item 4 and
    tests/unit/test_monte_carlo.py::FaultInjectorChiSquareTest).
    """

    def __init__(self,
                 sampler: Optional[MonteCarloSampler] = None,
                 seed: Optional[int] = None,
                 default_probability: float = 0.01) -> None:
        self.sampler = sampler or MonteCarloSampler(seed=seed)
        self.default_probability = float(default_probability)
        self._fires: int = 0
        self._trials: int = 0

    def should_fire(self, probability: Optional[float] = None) -> bool:
        """Return True with probability p (default: self.default_probability)."""
        p = float(self.default_probability if probability is None else probability)
        p = max(0.0, min(1.0, p))
        with self.sampler._lock:
            u = self.sampler._rng.random()
            self.sampler._draws_total += 1
            self._trials += 1
            fired = u < p
            if fired:
                self._fires += 1
            return fired

    def maybe_inject(self,
                     fault_fn: Callable[[], None],
                     probability: Optional[float] = None) -> bool:
        """Call ``fault_fn()`` stochastically; return whether it fired."""
        if self.should_fire(probability):
            try:
                fault_fn()
            except Exception:
                logger.debug("FaultInjector fault_fn raised", exc_info=True)
            return True
        return False

    def stats(self) -> dict[str, Any]:
        with self.sampler._lock:
            return {
                "trials": self._trials,
                "fires": self._fires,
                "empirical_rate": (self._fires / self._trials) if self._trials else 0.0,
                "default_probability": self.default_probability,
            }


class StochasticRateLimiter:
    """
    Probabilistic token-bucket rate limiter.

    Unlike the deterministic refill in a classic token bucket, replenishment
    here is a Poisson process with rate lambda tokens/second: at each call
    to ``consume()`` we draw the number of tokens that arrived since last
    call from a Poisson(lambda * dt) and add them. This matches research-A
    §2.6's "proof-of-work rate-limiting should be stochastic."

    Expected long-run throughput = lambda tokens/second; the S75 acceptance
    test (``StochasticRateLimiterTest::test_throughput_within_5pct``)
    verifies empirical throughput matches lambda within 5%.
    """

    def __init__(self,
                 rate_per_sec: float,
                 capacity: float = 64.0,
                 sampler: Optional[MonteCarloSampler] = None,
                 seed: Optional[int] = None,
                 time_fn: Optional[Callable[[], float]] = None) -> None:
        self.rate_per_sec = float(rate_per_sec)
        self.capacity = float(capacity)
        self.sampler = sampler or MonteCarloSampler(seed=seed)
        self.time_fn = time_fn or time.monotonic
        self._tokens: float = float(capacity)
        self._last_t: float = self.time_fn()
        self._lock = threading.RLock()
        self._granted: int = 0
        self._denied: int = 0

    def _refill(self, now: float) -> None:
        dt = max(0.0, now - self._last_t)
        self._last_t = now
        lam = self.rate_per_sec * dt
        if lam <= 0.0:
            return
        # Poisson draw using Knuth's method for small lambda; fall back to
        # exponential-approx for large lambda to avoid overflow.
        if lam < 30.0:
            L = math.exp(-lam)
            k = 0
            p = 1.0
            with self.sampler._lock:
                while True:
                    k += 1
                    p *= self.sampler._rng.random()
                    if p <= L:
                        break
                self.sampler._draws_total += k
            arrivals = k - 1
        else:
            # Normal approximation: mean=lam, var=lam.
            with self.sampler._lock:
                arrivals = max(0, int(round(
                    self.sampler._rng.gauss(lam, math.sqrt(lam)))))
                self.sampler._draws_total += 1
        self._tokens = min(self.capacity, self._tokens + arrivals)

    def consume(self, tokens: float = 1.0) -> bool:
        """Attempt to consume ``tokens``. Return True if granted."""
        now = self.time_fn()
        with self._lock:
            self._refill(now)
            if self._tokens >= tokens:
                self._tokens -= tokens
                self._granted += 1
                return True
            self._denied += 1
            return False

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "tokens": self._tokens,
                "capacity": self.capacity,
                "rate_per_sec": self.rate_per_sec,
                "granted": self._granted,
                "denied": self._denied,
            }


# --------------------------------------------------------------------------
# Process-wide samplers for daemon wiring
# --------------------------------------------------------------------------

_confidence_sampler: Optional[ConfidenceSampler] = None
_rollout_search: Optional[RolloutSearch] = None
_fault_injector: Optional[FaultInjector] = None
_rate_limiter: Optional[StochasticRateLimiter] = None


def get_confidence_sampler() -> Optional[ConfidenceSampler]:
    return _confidence_sampler


def get_rollout_search() -> Optional[RolloutSearch]:
    return _rollout_search


def get_fault_injector() -> Optional[FaultInjector]:
    return _fault_injector


def get_rate_limiter() -> Optional[StochasticRateLimiter]:
    return _rate_limiter


def register_samplers(seed: Optional[int] = None,
                      rate_per_sec: float = 10.0,
                      capacity: float = 64.0,
                      default_fault_probability: float = 0.0,
                      ) -> dict[str, Any]:
    """Install process-wide ConfidenceSampler / RolloutSearch / FaultInjector /
    StochasticRateLimiter singletons.  Tests and daemon both call this; the
    daemon passes seed=None (SystemRandom) while tests pin a seed.
    """
    global _confidence_sampler, _rollout_search
    global _fault_injector, _rate_limiter
    # Share a single MonteCarloSampler so one seed pins all four.
    shared = MonteCarloSampler(seed=seed)
    _confidence_sampler = ConfidenceSampler(sampler=shared)
    _rollout_search = RolloutSearch(sampler=shared)
    _fault_injector = FaultInjector(sampler=shared,
                                    default_probability=default_fault_probability)
    _rate_limiter = StochasticRateLimiter(
        rate_per_sec=rate_per_sec, capacity=capacity, sampler=shared)
    return {
        "confidence_sampler": _confidence_sampler,
        "rollout_search": _rollout_search,
        "fault_injector": _fault_injector,
        "rate_limiter": _rate_limiter,
        "sampler": shared,
    }


__all__ = [
    "MonteCarloSampler",
    "UncertaintyQuantifier",
    "UncertaintyResult",
    "ConfidenceSampler",
    "RolloutSearch",
    "RolloutResult",
    "FaultInjector",
    "StochasticRateLimiter",
    "register_with_daemon",
    "register_samplers",
    "get_quantifier",
    "get_confidence_sampler",
    "get_rollout_search",
    "get_fault_injector",
    "get_rate_limiter",
    "DEFAULT_N",
    "DEFAULT_N_BURN",
    "MIN_VALID_SAMPLES",
]
