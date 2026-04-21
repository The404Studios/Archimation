"""
Integration tests for the S68 Agent X ambiguity clarifier.

Validates that contusion.route() emits a `contusion.clarify` envelope when
an instruction has multiple near-tied handler candidates, and that exact
matches (set_smoke phrases) continue to dispatch normally without any
clarification layer in the way.

Matches the contract described in ai-control/daemon/contusion.py:
    * top1 confidence >= _CLARIFY_CONFIDENT    -> fast-path, no clarify
    * gap(top1, top2) >= _CLARIFY_GAP          -> no clarify
    * 2+ candidates within _CLARIFY_WINDOW of top1 AND top1 < _CLARIFY_CONFIDENT
                                               -> clarify envelope

Tests are HERMETIC. They build the dictionary_v2 artifact into pytest's
private tmp_path (mode 0700), point AICONTROL_DICTIONARY_V2_PATH at it, and
import contusion fresh so its module-level cached `_dict_v2` loads the test
artifact rather than any installed /usr/share copy.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
DAEMON_ROOT = REPO_ROOT / "ai-control" / "daemon"
if str(DAEMON_ROOT) not in sys.path:
    sys.path.insert(0, str(DAEMON_ROOT))


# Skip cleanly if dictionary_v2 isn't importable.
dictionary_v2 = pytest.importorskip(
    "dictionary_v2",
    reason="dictionary_v2 module not on sys.path",
)


@pytest.fixture(scope="module")
def v2_artifact(tmp_path_factory) -> Path:
    """Build the template->phrase artifact into a private tmpdir (mode 0700)."""
    tmp = tmp_path_factory.mktemp("clarify_v2")
    artifact = tmp / "dictionary_v2.pkl.zst"
    # Use compile_phrases + _resolve_best + _build_artifact directly so we
    # don't shell out.
    phrases = dictionary_v2.compile_phrases()
    resolved = dictionary_v2._resolve_best(phrases)
    dictionary_v2._build_artifact(
        {
            "version": 2,
            "phrase_count": len(resolved),
            "phrases": resolved,
        },
        str(artifact),
    )
    assert artifact.exists() and artifact.stat().st_size > 0
    return artifact


@pytest.fixture(scope="module")
def contusion_mod(v2_artifact, monkeypatch_module):
    """Import contusion fresh with AICONTROL_DICTIONARY_V2_PATH set.

    We need module scope (re-import per module, not per test) because
    dictionary_v2 caches _PHRASES at module load. Changing the path after
    import would be ignored.
    """
    monkeypatch_module.setenv(
        "AICONTROL_DICTIONARY_V2_PATH", str(v2_artifact)
    )
    monkeypatch_module.setenv("AICONTROL_STRICT_CONTRACT", "warn")

    # Clear any cached load in dictionary_v2 from prior test modules.
    dictionary_v2._PHRASES = None
    dictionary_v2._LOAD_PATH = None
    dictionary_v2._LOAD_ERROR = None

    # Reload contusion so its module-level _dict_v2 sees the freshly-pointed
    # artifact. (contusion holds a reference to the dictionary_v2 module,
    # not to the artifact directly, so reloading contusion is enough.)
    if "contusion" in sys.modules:
        importlib.reload(sys.modules["contusion"])
    import contusion as mod
    return mod


@pytest.fixture(scope="module")
def monkeypatch_module():
    """Module-scoped monkeypatch (pytest's default monkeypatch is function-scoped)."""
    mp = pytest.MonkeyPatch()
    yield mp
    mp.undo()


def _route(cn_mod, phrase: str) -> dict:
    cn = cn_mod.Contusion()
    return asyncio.run(cn.route(phrase))


# ------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------


EXACT_MATCHES = [
    "mute",
    "volume up",
    "volume down",
    "lock screen",
    "list services",
    "list drivers",
    "max brightness",
    "next song",
]


@pytest.mark.parametrize("phrase", EXACT_MATCHES)
def test_exact_match_does_not_clarify(contusion_mod, phrase):
    """High-confidence v2 hits (conf >= 0.9) must bypass the clarifier."""
    resp = _route(contusion_mod, phrase)
    assert resp.get("handler_type") != "contusion.clarify", (
        f"{phrase!r} unexpectedly returned clarify envelope: {resp!r}"
    )
    # Exact matches should still report v2_template source on success.
    assert resp.get("source") == "v2_template", (
        f"{phrase!r} expected source=v2_template, got {resp.get('source')!r}"
    )


AMBIGUOUS = [
    # "volume" alone has volume_up + volume_down within _CLARIFY_WINDOW.
    "volume",
    # "brightness" alone has up/down/get/max/min tied very close.
    "brightness",
    # "audio" ties volume_up and volume_down at the same confidence.
    "audio",
    # "down" is a partial-substring across audio.volume_down + brightness.down.
    "down",
]


@pytest.mark.parametrize("phrase", AMBIGUOUS)
def test_ambiguous_phrase_returns_clarify(contusion_mod, phrase):
    """Near-tied candidates without a clear winner must emit clarify."""
    resp = _route(contusion_mod, phrase)
    assert resp.get("handler_type") == "contusion.clarify", (
        f"{phrase!r} expected clarify envelope, got handler_type="
        f"{resp.get('handler_type')!r}; full response={resp!r}"
    )
    # Envelope contract: success=False, has asking text, has >=2 candidates,
    # actions list is empty so set_smoke's extractor skips dispatch.
    assert resp.get("success") is False
    assert resp.get("source") == "clarification"
    assert resp.get("original_phrase") == phrase
    cands = resp.get("candidates") or []
    assert len(cands) >= 2, f"expected >=2 candidates, got {cands!r}"
    for c in cands:
        assert "handler_type" in c
        assert "confidence" in c
        assert isinstance(c["confidence"], float)
    asking = resp.get("asking") or ""
    assert asking.startswith("Did you mean "), (
        f"'asking' text malformed: {asking!r}"
    )
    assert asking.endswith("?")
    # Must NOT include an 'error' field — ambiguity is a signal, not a fault.
    assert "error" not in resp
    # actions/results must be empty so dispatchers see "no action executed".
    assert resp.get("actions") == []
    assert resp.get("results") == []


def test_clarify_envelope_pretty_renders_handler_names(contusion_mod):
    """asking text should convert handler_type dots/underscores to readable form."""
    resp = _route(contusion_mod, "volume")
    assert resp.get("handler_type") == "contusion.clarify"
    asking = resp["asking"]
    # audio.volume_up -> "volume up (audio)" via _pretty_handler
    assert "volume up (audio)" in asking or "volume down (audio)" in asking, (
        f"pretty-render missing from {asking!r}"
    )


def test_lookup_multi_returns_sorted_topk():
    """dictionary_v2.lookup_multi contract: sorted desc, <= top_k, right shape."""
    res = dictionary_v2.lookup_multi("volume", top_k=3)
    assert isinstance(res, list)
    assert len(res) <= 3
    assert len(res) >= 1
    for entry in res:
        assert set(entry.keys()) >= {"handler_type", "confidence", "source"}
        assert isinstance(entry["handler_type"], str)
        assert isinstance(entry["confidence"], float)
        assert entry["source"] == "v2_template"
    # Sorted descending by confidence.
    confs = [e["confidence"] for e in res]
    assert confs == sorted(confs, reverse=True)


def test_lookup_multi_empty_input_returns_empty_list():
    assert dictionary_v2.lookup_multi("") == []
    assert dictionary_v2.lookup_multi(None) == []
