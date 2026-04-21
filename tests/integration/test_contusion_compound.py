"""
Integration tests for Contusion compound-phrase routing (S68 Agent T).

Exercises the `_route_compound` / `_split_compound` path of contusion.Contusion
that splits a natural-language instruction on a conjunction marker (and/then/
after that/followed by/;/&) and dispatches each sub-phrase independently via
the existing Stage-1 v2 lookup. Responses carry an ordered `actions[]` list.

These tests are HERMETIC: in-memory only. No daemon, no network, no real
subprocess of any consequence (the leaves like `audio.mute_toggle` may shell
out to `pactl`, but on the CI box that's a no-op with a structured error --
we assert on the routing envelope, not the execution result).

Import strategy mirrors test_dictionary_v2.py: add ai-control/daemon to
sys.path before importing contusion, and pytest.importorskip if the module
isn't on disk yet.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest


# Add the daemon source dir to sys.path so `import contusion` resolves
# regardless of where pytest is invoked from. Mirrors the conftest.py /
# test_markov_chains.py / test_dictionary_v2.py pattern.
REPO_ROOT = Path(__file__).resolve().parents[2]
DAEMON_ROOT = REPO_ROOT / "ai-control" / "daemon"
if str(DAEMON_ROOT) not in sys.path:
    sys.path.insert(0, str(DAEMON_ROOT))


# Don't want to explode on a legit single-leaf fallback during these tests --
# the S68 default is "warn", but some CI runners may have set "raise".
os.environ.setdefault("AICONTROL_STRICT_CONTRACT", "warn")


contusion = pytest.importorskip(
    "contusion",
    reason="ai-control/daemon/contusion.py must be on sys.path",
)


@pytest.fixture(scope="module")
def cn():
    """One Contusion instance per test module."""
    return contusion.Contusion()


def _route(cn, phrase):
    """Small sync helper around the async route() method."""
    return asyncio.run(cn.route(phrase))


# -----------------------------------------------------------------------------
# Core compound cases -- each should split into >= 2 leaves and emit
# an ordered actions[] whose handler_types match expectation.
# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "phrase, expected_count, expected_handler_types",
    [
        (
            "mute and lock screen",
            2,
            ["audio.mute_toggle", "power.lock_screen"],
        ),
        (
            "volume up then volume down",
            2,
            ["audio.volume_up", "audio.volume_down"],
        ),
        (
            "mute; volume up",
            2,
            ["audio.mute_toggle", "audio.volume_up"],
        ),
        (
            "volume up & volume down",
            2,
            ["audio.volume_up", "audio.volume_down"],
        ),
        (
            "mute and volume down and lock screen",
            3,
            ["audio.mute_toggle", "audio.volume_down", "power.lock_screen"],
        ),
    ],
)
def test_compound_splits_and_dispatches(
    cn, phrase, expected_count, expected_handler_types
):
    r = _route(cn, phrase)
    assert isinstance(r, dict), f"route() must return a dict, got {type(r)}"
    assert r.get("source") == "compound", (
        f"{phrase!r}: expected source=compound, got {r.get('source')!r} "
        f"(full envelope: {r})"
    )
    assert r.get("handler_type") == "compound"
    assert r.get("compound_count") == expected_count, (
        f"{phrase!r}: expected compound_count={expected_count}, "
        f"got {r.get('compound_count')}"
    )
    actions = r.get("actions", [])
    actual_hts = [a.get("handler_type") for a in actions]
    assert actual_hts == expected_handler_types, (
        f"{phrase!r}: actions handler_types mismatch: "
        f"expected {expected_handler_types}, got {actual_hts}"
    )
    # Sub-results must be present and preserve order.
    results = r.get("results", [])
    assert len(results) == expected_count
    # Each result carries the phrase it was routed from.
    for leaf_result in results:
        assert "phrase" in leaf_result


# -----------------------------------------------------------------------------
# Negative cases -- must NOT be split into compound even though "and" or
# "then" appears as a substring or word.
# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "phrase",
    [
        # Single-intent phrases with no conjunction at all.
        "mute",
        "volume up",
        "lock screen",
        "take a screenshot",
        # Conjunction-looking phrases that should NOT split.
        # "understand" contains "and" as a substring but not as a word.
        "understand this",
        # "ACME Research and Development" -- proper-noun false-positive.
        # Both sides must be multi-token OR have a handler-trigger verb;
        # "Development" is a single token and has no verb, so no split.
        "ACME Research and Development",
    ],
)
def test_non_compound_falls_through_to_single_intent(cn, phrase):
    r = _route(cn, phrase)
    assert isinstance(r, dict)
    # The salient property: source is NOT "compound" and compound_count
    # is absent (or 1 if someone tried to split and bailed).
    assert r.get("source") != "compound", (
        f"{phrase!r} should NOT route as compound, got envelope: {r}"
    )
    assert r.get("compound_count") is None or r.get("compound_count") <= 1


# -----------------------------------------------------------------------------
# Backwards-compat: a phrase that v2 hits on directly (single intent) must
# return exactly the same envelope it did before this change.
# -----------------------------------------------------------------------------
def test_single_v2_hit_unchanged(cn):
    r = _route(cn, "mute")
    assert r.get("source") == "v2_template"
    assert r.get("handler_type") == "audio.mute_toggle"
    # actions[] has exactly one entry matching the top-level handler_type.
    actions = r.get("actions", [])
    assert len(actions) == 1
    assert actions[0].get("handler_type") == "audio.mute_toggle"


# -----------------------------------------------------------------------------
# Depth cap: long chain "A and B and C and D and E" -- caller protection
# against adversarial input. Must return a compound dict without recursing
# past _COMPOUND_MAX_DEPTH = 3.
# -----------------------------------------------------------------------------
def test_deep_chain_bounded_by_depth_cap(cn):
    r = _route(cn, "mute and volume up and volume down and lock screen and mute")
    assert r.get("source") == "compound"
    # Must return SOMETHING sensible -- not hang, not stack-overflow.
    # Depth cap is 3 so we may get fewer leaves than the 5 ands would imply,
    # with the deep tail collapsed to a single leaf. That's acceptable.
    assert r.get("compound_count") is not None
    assert r.get("compound_count") >= 2
    assert isinstance(r.get("results"), list)


# -----------------------------------------------------------------------------
# Mixed routing: one leaf resolves via dictionary_v2, the other falls
# through the cascade. Compound envelope MUST be emitted regardless.
# -----------------------------------------------------------------------------
def test_mixed_v2_and_fallback_leaves(cn):
    # "take a screenshot" hits v2; "open the browser" falls through
    # (no v2 entry) and may or may not resolve via stage-2 dictionary.
    r = _route(cn, "take a screenshot and open the browser")
    assert r.get("source") == "compound"
    assert r.get("compound_count") == 2
    # actions[] lists only leaves that produced a handler_type -- this one
    # has at least the screenshot leaf. The browser leaf may or may not
    # produce a handler_type depending on what stage-2 catches.
    actions = r.get("actions", [])
    hts = [a.get("handler_type") for a in actions]
    assert "system.screenshot_full" in hts
    # Regardless of dispatch outcome, results[] has both leaves.
    assert len(r.get("results", [])) == 2


# -----------------------------------------------------------------------------
# The _split_compound helper is pure and easy to unit-test directly.
# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "phrase, expected_leaves",
    [
        ("mute and lock screen", ["mute", "lock screen"]),
        ("mute; volume up", ["mute", "volume up"]),
        ("A and B", ["A and B"]),  # 1 token each, no verb -> no split
        ("mute", ["mute"]),
        ("", []),
        (
            "volume up then volume down",
            ["volume up", "volume down"],
        ),
    ],
)
def test_split_compound_direct(cn, phrase, expected_leaves):
    assert cn._split_compound(phrase) == expected_leaves
