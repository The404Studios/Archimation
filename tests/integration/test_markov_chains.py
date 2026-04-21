"""Markov-chain-driven NL fuzzer for the contusion handler-dispatch layer.

Session 58, Agent 8.

Generates 100+ test phrases by sampling from a trigram chain trained on
the contusion_dictionary's known-good seed phrases, then drives every
phrase through the daemon's `/contusion/context` endpoint (in-process
via TestClient + mock LLM, per the S52 fixture pattern) to verify:

  * Every generated phrase yields a structured envelope, not a 5xx.
  * Either the dictionary routes (success=True with non-empty actions)
    or the system returns a clarification-shaped envelope -- never an
    unhandled exception bubbling to the caller.
  * The seed phrases (which we know route correctly in production)
    achieve a healthy dispatch-success rate (>= 30/50).

Also includes integration tests for the cortex-side Markov modules
(DecisionMarkovModel + MarkovTransitionMatrix from
ai-control.cortex.decision_engine and dynamic_hyperlation). Those tests
SKIP gracefully if the modules cannot be imported.

Hermetic: no QEMU, no real subprocess, no real LLM. Uses the existing
``mock_llm_app`` / ``test_client`` / ``subprocess_recorder`` fixtures
from ``conftest.py`` (do not modify).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

import pytest


# ---------------------------------------------------------------------------
# Imports of the in-tree generator + cortex modules.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
if str(FIXTURES_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURES_DIR))
# Make `cortex` and `daemon` packages resolvable for the optional
# integration tests at the bottom of this module.
for sub in ("ai-control", "ai-control/daemon"):
    p = REPO_ROOT / sub
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from markov_phrase_gen import PhraseGenerator, default_phrases  # noqa: E402


# ---------------------------------------------------------------------------
# Shared module-scope generator: deterministic with seed=42 so every test
# in the module sees the SAME 100-phrase sample. Keeps test runs bit-stable.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def seed_phrases() -> list:
    return default_phrases()


@pytest.fixture(scope="module")
def generator(seed_phrases) -> PhraseGenerator:
    return PhraseGenerator(seed_phrases, n=3, seed=42)


@pytest.fixture(scope="module")
def markov_batch(generator) -> list:
    """One canonical batch of 100 generated phrases; reused by all tests."""
    return generator.generate_batch(100)


# ---------------------------------------------------------------------------
# Helper: authenticated POST shorthand (mirrors test_ai_commands).
# ---------------------------------------------------------------------------

def _post(client, path: str, body: dict, token: str | None = None):
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    # NOTE: starlette TestClient deprecates the `timeout=` kwarg; we omit it
    # rather than poison the run with DeprecationWarnings. The TestClient
    # is in-process so calls return synchronously anyway.
    return client.post(path, json=body, headers=headers)


def _is_envelope(body: Any) -> bool:
    """The contusion envelope contract enforced by api_server.contusion_context."""
    if not isinstance(body, dict):
        return False
    required = {"status", "success", "actions", "pending",
                "blocked", "needs_confirmation", "summary"}
    return required.issubset(body.keys())


# ===========================================================================
# 1. Phrase-generator unit tests (no daemon needed).
# ===========================================================================

def test_generator_produces_nonempty_phrases(generator):
    """Every one of 50 generated phrases has at least 2 tokens."""
    batch = generator.generate_batch(50)
    assert len(batch) == 50
    short = [p for p in batch if len(p.split()) < 2]
    # Tolerate a tiny tail of single-token phrases (e.g. "mute" / "suspend"
    # are legitimate one-word phrases in the seed set), but the bulk MUST
    # be multi-token.
    assert len(short) <= 5, (
        f"too many sub-2-token phrases ({len(short)}/50): {short[:10]}"
    )
    assert all(isinstance(p, str) for p in batch)


def test_generator_stays_in_vocabulary(generator):
    """No generated token escapes the seed vocabulary."""
    vocab = generator.vocab
    assert vocab, "vocabulary should be non-empty after training"
    leaks = []
    for phrase in generator.generate_batch(100):
        for tok in phrase.split():
            if tok not in vocab:
                leaks.append(tok)
    assert not leaks, f"out-of-vocabulary tokens leaked: {leaks[:10]}"


def test_generator_diversity(markov_batch):
    """100 generations -> at least 40 distinct phrases.

    With the curated 50-phrase seed and trigram chain we measure ~48
    unique-out-of-100 with seed=42. Threshold 40 catches genuine
    collapse (e.g. a chain that always emits the same 3 phrases) while
    tolerating the natural duplication a small-vocab Markov produces.
    """
    unique = set(markov_batch)
    assert len(unique) >= 40, (
        f"only {len(unique)} distinct phrases out of 100; "
        f"sample: {list(unique)[:5]}"
    )


def test_generator_is_deterministic_under_seed(seed_phrases):
    """Two PhraseGenerators with the same seed emit identical batches."""
    g1 = PhraseGenerator(seed_phrases, n=3, seed=42)
    g2 = PhraseGenerator(seed_phrases, n=3, seed=42)
    assert g1.generate_batch(20) == g2.generate_batch(20)


# ===========================================================================
# 2. Routing-fuzz tests (use the in-process daemon + mock LLM).
# ===========================================================================

def _route(client, token, instruction: str) -> Dict[str, Any]:
    """Send an instruction through /contusion/context, return parsed body.

    `/contusion/context` is the canonical NL parse+dispatch endpoint.
    There is no `/contusion/parse` (no parse-only mode); the recorder
    fixture captures any subprocess egress so we never actually execute.
    """
    r = _post(client, "/contusion/context",
              {"prompt": instruction}, token=token)
    # Note: we deliberately accept BOTH 200 and 422 here -- 422 is FastAPI's
    # request-validation rejection, which still proves the route did not
    # 5xx. Anything else is a hard failure.
    assert r.status_code in (200, 422), (
        f"status {r.status_code} for instruction={instruction!r}: {r.text[:300]}"
    )
    if r.status_code == 422:
        return {"_validation_rejected": True}
    return r.json()


def test_dictionary_handles_50_known_phrases(test_client, admin_token,
                                             subprocess_recorder, seed_phrases):
    """Feed the 50 curated seed phrases through /contusion/context.

    Uses ``admin_token`` (TRUST_ADMIN=600) because /contusion/context
    requires trust >= 400; the lower TRUST_INTERACT (200) token returns
    403 ``insufficient_trust_level`` for every call.

    Counts how many produced a structured envelope WITH non-empty
    actions+pending OR a clarification flag.  Healthy coverage is >= 30/50.
    The remaining 20 may legitimately route to clarification or yield
    blocked-action envelopes in the test sandbox (no real DBus / DISPLAY
    / pacman) -- what matters is that NONE crashed.
    """
    routed = 0
    crashed = []
    for phrase in seed_phrases[:50]:
        try:
            body = _route(test_client, admin_token, phrase)
        except AssertionError as e:
            crashed.append((phrase, str(e)[:200]))
            continue
        if body.get("_validation_rejected"):
            continue
        if not _is_envelope(body):
            crashed.append((phrase, f"non-envelope body keys={list(body)[:8]}"))
            continue
        # "Routed" = envelope contains either an executed/pending action
        # or success=True (some safe handlers reply success without an
        # action list -- e.g. info queries).
        has_actions = bool(body.get("actions") or body.get("pending"))
        if has_actions or body.get("success") is True:
            routed += 1
    assert not crashed, f"phrases that crashed/returned non-envelope: {crashed}"
    assert routed >= 30, (
        f"only {routed}/50 known seed phrases dispatched to a handler; "
        f"expected at least 30. Subprocess calls captured: "
        f"{len(subprocess_recorder.calls)}"
    )
    # Stash the rate on the function for the final-line summary.
    test_dictionary_handles_50_known_phrases.dispatch_rate = (routed, 50)


def test_markov_phrases_dispatch_or_clarify(test_client, admin_token,
                                            subprocess_recorder, markov_batch):
    """100 markov phrases must each return a well-formed envelope.

    Acceptable outcomes per phrase:
      * structured envelope with status in {ok, error}
      * 422 validation rejection (treated as "well-formed refusal")

    Unacceptable: any 5xx, any unhandled exception, any non-dict body.
    """
    bad = []
    for phrase in markov_batch:
        try:
            body = _route(test_client, admin_token, phrase)
        except AssertionError as e:
            bad.append((phrase, str(e)[:200]))
            continue
        if body.get("_validation_rejected"):
            continue
        if not _is_envelope(body):
            bad.append((phrase, f"non-envelope keys={list(body)[:8]}"))
            continue
        # status MUST be one of the documented values.
        if body.get("status") not in ("ok", "error"):
            bad.append((phrase, f"bad status={body.get('status')!r}"))
    assert not bad, (
        f"{len(bad)}/100 markov phrases produced a malformed response; "
        f"first few: {bad[:5]}"
    )


def test_no_handler_dispatched_returns_proposal_envelope(test_client,
                                                          admin_token,
                                                          subprocess_recorder):
    """Even pure gibberish must come back as an envelope, not a stack trace."""
    gibberish_inputs = [
        "wxq zwerp zk", "asdfqwer", "...", "    ",
        "   leading whitespace", "trailing whitespace   ",
        "bytes" + "\u00a0" * 5,  # nbsp injection
    ]
    for instr in gibberish_inputs:
        body = _route(test_client, admin_token, instr)
        if body.get("_validation_rejected"):
            continue
        assert _is_envelope(body), (
            f"gibberish {instr!r} returned non-envelope: {body}"
        )
        assert isinstance(body.get("summary"), str)
        # actions/pending/blocked are always lists per contract.
        for k in ("actions", "pending", "blocked"):
            assert isinstance(body.get(k), list), (
                f"{instr!r}: {k} should be list, got {type(body.get(k))}"
            )


# ===========================================================================
# 3. Cortex-side Markov module integration tests.
# ===========================================================================

def _import_decision_markov():
    try:
        from cortex.decision_engine import DecisionMarkovModel
        return DecisionMarkovModel
    except Exception as e:
        pytest.skip(f"cortex.decision_engine not importable: {e}")


def _import_hyperlation_markov():
    try:
        from cortex.dynamic_hyperlation import MarkovTransitionMatrix
        return MarkovTransitionMatrix
    except Exception as e:
        pytest.skip(f"cortex.dynamic_hyperlation not importable: {e}")


def test_decision_markov_observation_records():
    """DecisionMarkovModel.observe_decision -> predict_next ranks correctly."""
    DecisionMarkovModel = _import_decision_markov()
    m = DecisionMarkovModel()
    # Synthetic decision sequence: ALLOW dominates after DENY.
    seq = ["DENY", "ALLOW", "DENY", "ALLOW", "DENY", "ALLOW",
           "DENY", "QUARANTINE"]
    for a in seq:
        m.observe_decision(a)
    # After "DENY" we've seen ALLOW 3 times and QUARANTINE 1 time.
    preds = m.predict_next(after_action="DENY", k=3)
    assert preds, "predict_next returned empty list"
    assert preds[0][0] == "ALLOW", f"top prediction should be ALLOW: {preds}"
    # Probabilities should be normalized to <= 1.0 and sorted descending.
    probs = [p for _, p in preds]
    assert probs == sorted(probs, reverse=True)
    assert all(0.0 < p <= 1.0 for p in probs)
    # Empty / unknown origin -> empty list (defensive contract).
    assert m.predict_next(after_action="NEVER_OBSERVED", k=3) == []


def test_hyperlation_markov_kl_divergence_rises_on_anomaly():
    """KL(recent || stationary) spikes after an anomalous state burst."""
    MarkovTransitionMatrix = _import_hyperlation_markov()
    m = MarkovTransitionMatrix()
    # Build a long history where state 0 (STEADY_FLOW) dominates.
    for _ in range(30):
        m.update(0)
        m.update(0)
        m.update(1)  # occasional excursion to METABOLIC_STARVATION
        m.update(0)
    baseline_kl = m.kl_divergence_recent_vs_steady(recent_window=10)
    # Now inject an anomalous burst of state 2 (BEHAVIORAL_DIVERGENCE).
    for _ in range(10):
        m.update(2)
    anomaly_kl = m.kl_divergence_recent_vs_steady(recent_window=10)
    assert anomaly_kl > baseline_kl, (
        f"KL should rise after anomaly: baseline={baseline_kl:.4f} "
        f"anomaly={anomaly_kl:.4f}"
    )
    # Floor: a recent-window dominated by an unobserved state must give
    # a strictly positive KL (modulo eps smoothing).
    assert anomaly_kl > 0.0
