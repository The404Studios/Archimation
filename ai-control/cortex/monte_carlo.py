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

    # ---- HTTP metric endpoint  (best-effort) ------------------------------
    if app is not None:
        try:
            @app.get("/metrics/monte_carlo")
            async def _mc_metrics():   # type: ignore[unused-ignore]
                return uq.metrics()
        except AttributeError:
            # Not a FastAPI app (unit-test stub).  Silently skip.
            logger.debug("register_with_daemon: app lacks .get; skipping HTTP route")
        except Exception:
            logger.debug("HTTP route registration failed", exc_info=True)

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


__all__ = [
    "MonteCarloSampler",
    "UncertaintyQuantifier",
    "UncertaintyResult",
    "register_with_daemon",
    "get_quantifier",
    "DEFAULT_N",
    "DEFAULT_N_BURN",
    "MIN_VALID_SAMPLES",
]
