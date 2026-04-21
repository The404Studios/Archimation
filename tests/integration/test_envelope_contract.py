"""
S68 runtime envelope contract.

Every successful route through contusion.py MUST return an entry with:
  - handler_type: str (non-empty)
  - either (success bool) or (actions list) — legacy-shell-exec uses both
  - confidence: float in [0.0, 1.0]
"""
import sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "ai-control" / "daemon"))

import pytest

contusion = pytest.importorskip("contusion")


ROUTE_SAMPLES = [
    "raise the volume",
    "lock the screen",
    "take a screenshot",
    "list services",
    "type hello",
    "press enter",
    "show clipboard",
    "brightness up",
    "mute",
    "pause music",
]


@pytest.mark.parametrize("phrase", ROUTE_SAMPLES)
def test_every_route_has_handler_type(phrase):
    # Call the routing function — the exact entry point varies; try the
    # public process-context helper first, then fall back to _route_dictionary.
    if hasattr(contusion, "route_phrase"):
        resp = contusion.route_phrase(phrase)
    elif hasattr(contusion, "_route_dictionary"):
        resp = contusion._route_dictionary(phrase)
    else:
        pytest.skip("no known routing entry point in contusion module")
    assert resp is not None, f"{phrase} returned None"
    # Envelope shape may be a dict with a top-level handler_type, a list of
    # actions each with handler_type, or a structured proposal.
    ht = _extract_handler_type(resp)
    assert ht, f"{phrase} → response has no handler_type: {resp!r}"
    assert isinstance(ht, str) and len(ht) > 0, f"{phrase} → handler_type not a non-empty string"


def _extract_handler_type(resp):
    if isinstance(resp, dict):
        if resp.get("handler_type"):
            return resp["handler_type"]
        actions = resp.get("actions") or []
        for a in actions:
            ht = a.get("handler_type") if isinstance(a, dict) else getattr(a, "handler_type", None)
            if ht:
                return ht
    if isinstance(resp, list):
        for a in resp:
            ht = a.get("handler_type") if isinstance(a, dict) else getattr(a, "handler_type", None)
            if ht:
                return ht
    ht = getattr(resp, "handler_type", None)
    return ht
