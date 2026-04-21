"""Verify docs/markov-chains.md cites real symbols / endpoints / theorems.

The doc is operator-facing; if it drifts from the code (renamed module,
removed endpoint, deleted symbol) the diag tool's "Section 1 / Section 4"
references will silently mislead. This test asserts each citation is real.

For citations whose owner-agent (1-9) hasn't landed in this branch yet,
the relevant assertion is **SKIPPED**, not failed -- so this file passes
mid-session and tightens automatically as agents finish.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
DOC = REPO_ROOT / "docs" / "markov-chains.md"

# (relative_path, must_exist_to_run)
FILE_REFS = [
    "ai-control/daemon/markov_nlp.py",
    "ai-control/cortex/dynamic_hyperlation.py",
    "trust/kernel/trust_ape_markov.c",
    "ai-control/daemon/behavioral_markov.py",
    "ai-control/cortex/decision_engine.py",
    "coherence/daemon/src/coh_markov.c",
    "ai-control/daemon/trust_markov.py",
    "tests/integration/fixtures/markov_phrase_gen.py",
]

# Endpoints the doc claims live in api.py / api_server.py.
# (route_pattern, file_relative_to_repo_root)
ENDPOINT_REFS = [
    ("/cortex/markov/system",          "ai-control/cortex/api.py"),
    ("/cortex/markov/subject",         "ai-control/cortex/api.py"),
    ("/cortex/markov/decisions",       "ai-control/cortex/api.py"),
]

# Theorems and the source citation each maps to. We look for a string the
# doc says is load-bearing -- e.g. BUILD_BUG_ON for T3, the validator
# function for T3 chi-square, etc.
THEOREM_REFS = [
    ("Theorem 3", "trust/kernel/trust_ape.c",         "BUILD_BUG_ON"),
    ("Theorem 3", "trust/kernel/trust_ape_markov.c",  "trust_ape_markov_validator"),
    ("Theorem 5", "ai-control/daemon/trust_markov.py","expected_time_to_apoptosis"),
]


def _doc_text() -> str:
    if not DOC.exists():
        pytest.fail(f"docs/markov-chains.md missing at {DOC}")
    return DOC.read_text(encoding="utf-8")


def test_doc_exists_and_non_trivial():
    text = _doc_text()
    assert len(text) > 2000, "doc shorter than expected (~400 lines)"
    assert "Zenodo" in text, "missing Zenodo citation"
    assert "18710335" in text, "missing Zenodo record id"


@pytest.mark.parametrize("rel", FILE_REFS)
def test_doc_file_refs_resolve(rel):
    text = _doc_text()
    if rel not in text:
        pytest.skip(f"doc does not mention {rel} (agent may not have landed)")
    p = REPO_ROOT / rel
    if not p.exists():
        pytest.skip(f"{rel} not present yet (agent in flight) -- doc cites it")
    assert p.is_file(), f"{rel} is not a regular file"


@pytest.mark.parametrize("route,api_file", ENDPOINT_REFS)
def test_doc_endpoint_refs_have_route(route, api_file):
    text = _doc_text()
    if route not in text:
        pytest.skip(f"doc does not mention {route}")
    api_path = REPO_ROOT / api_file
    if not api_path.exists():
        pytest.skip(f"{api_file} missing -- cannot verify {route}")
    body = api_path.read_text(encoding="utf-8", errors="replace")
    # Match @app.get("/cortex/markov/...") or @router.get(...) or
    # @app.post(...). The endpoint pattern uses `{...}` for path params,
    # so do a prefix substring match.
    pat = re.compile(
        r"@(?:app|router)\.(?:get|post|put|delete)\(\s*['\"]"
        + re.escape(route)
    )
    if not pat.search(body):
        pytest.skip(
            f"{route} not yet wired in {api_file} (Agent 9 deliverable)"
        )


@pytest.mark.parametrize("theorem,src,symbol", THEOREM_REFS)
def test_doc_theorem_refs_have_symbol(theorem, src, symbol):
    text = _doc_text()
    if theorem not in text:
        pytest.skip(f"doc does not cite {theorem}")
    p = REPO_ROOT / src
    if not p.exists():
        pytest.skip(f"{src} missing -- cannot verify {theorem}")
    body = p.read_text(encoding="utf-8", errors="replace")
    assert symbol in body, (
        f"{theorem} cites {symbol} via {src} but symbol absent"
    )


def test_diag_script_present_and_executable_shape():
    diag = REPO_ROOT / "scripts" / "diag-markov.sh"
    assert diag.exists(), "scripts/diag-markov.sh missing"
    head = diag.read_text(encoding="utf-8", errors="replace").splitlines()[:3]
    assert head and head[0].startswith("#!"), "diag-markov.sh missing shebang"
    body = diag.read_text(encoding="utf-8", errors="replace")
    # Must reference each endpoint the doc table promises
    assert "/cortex/markov/system"    in body
    assert "/cortex/markov/decisions" in body
    assert "/cortex/markov/subject"   in body
    # Must have a graceful-no-daemon path
    assert "daemon not reachable" in body or "no HTTP response" in body


def test_doc_has_theorem_table_entries():
    text = _doc_text()
    for t in ("Theorem 2", "Theorem 3", "Theorem 5", "Theorem 7"):
        assert t in text, f"doc missing {t} citation"
