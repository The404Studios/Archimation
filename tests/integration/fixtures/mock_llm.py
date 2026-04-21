"""Mock LLM module — drop-in replacement for ai-control/daemon/llm.py
used by the AI-commands functional test harness.

Session 52 (Agent Z).

Contract (mirrors daemon/llm.py signatures that get called in-process):
  - _model               : non-None sentinel so daemon's "model loaded?" checks pass
  - _loaded              : True  (deliberately exposed per test spec)
  - _llm_disabled()      : returns False so the daemon's opt-out gate stays OFF
  - get_status()         : static dict {"status":"loaded","model":"mock"}
  - generate(prompt, max_tokens, temperature, timeout, stop)
        -> str (scripted JSON)   (used by contusion._route_via_llm + ai_planner.plan)
  - query(prompt, max_tokens, temperature, **kw)
        -> dict (per spec)        (surfaced for callers that want a status envelope)
  - analyze_binary(path, **kw)
        -> dict (fixed advisory)  (binary_signatures integration)

Prompt-matching rules (substring, case-insensitive):
  "screenshot"         -> screenshot single-step JSON (confidence 0.95)
  "install firefox"    -> single-step app.install_firefox JSON (confidence 0.92)
  "complex multi-step" -> planner-shaped JSON with 2 steps + depends_on chain
Anything else          -> low-confidence fallback (confidence 0.10) so the
                          daemon returns needs_clarification=True.

All scripted outputs are STRICT JSON strings — the real code paths
(Contusion._llm_extract_json and ai_planner._extract_json) parse them the
same way they'd parse a real model's reply, so the test exercises the
full prompt -> model -> parse -> validate -> dispatch round-trip.
"""
from __future__ import annotations

import json
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Sentinel values the daemon's live code checks via getattr / import.
# ---------------------------------------------------------------------------

# Non-None so contusion._route_via_llm's `getattr(_llm_mod, "_model", None) is None`
# guard does NOT short-circuit. The sentinel is never called; generate() is.
_model: Any = object()

# Expose per-spec flag; the daemon doesn't use this name but the test spec
# pins it so downstream integrations can cheaply probe "are we mocked?".
_loaded: bool = True


def _llm_disabled() -> bool:
    """Override the daemon's LLM_DISABLED env probe.

    daemon/llm.py reads LLM_DISABLED from the environment; we return False
    unconditionally so the mock cannot be accidentally turned off by a
    stray test env var. Tests that WANT LLM disabled should patch
    `_llm_disabled` on the injected module instead.
    """
    return False


def get_status() -> dict:
    """Mirror daemon/llm.py get_status() shape, flagging the mock."""
    return {
        "status": "loaded",
        "model": "mock",
        "llama_cpp_available": True,
        "model_loaded": True,
        "model_path": "<mock>",
    }


# ---------------------------------------------------------------------------
# Scripted prompt -> JSON mapping.
# ---------------------------------------------------------------------------

_SCREENSHOT_JSON = json.dumps({
    "handler_type": "screenshot",
    "args": {},
    "confidence": 0.95,
    "rationale": "matched screenshot pattern in prompt",
})

_INSTALL_FIREFOX_JSON = json.dumps({
    "handler_type": "app.install_firefox",
    "args": {},
    "confidence": 0.92,
    "rationale": "matched install firefox pattern in prompt",
})

# Planner-shape response: a top-level "steps" array. Note the planner
# validates handler_type against contusion_handlers.HANDLERS — the real
# registry has app.install_steam (no firefox), so we use handler names
# that exist. Test keeps "install firefox" string keying for the
# single-step case since it only needs contusion._route_via_llm's
# catalog validation, which includes the static fallback list where
# app.install_firefox is NOT present but the test checks needs_clarification.
# For the multi-step test we use handlers that ARE in the live registry.
_MULTISTEP_JSON = json.dumps({
    "summary": "install steam then launch it",
    "steps": [
        {
            "handler_type": "app.install_steam",
            "args": {},
            "depends_on": [],
            "rationale": "step 1: install the package",
        },
        {
            "handler_type": "app.launch",
            "args": {"name": "steam"},
            "depends_on": [0],
            "rationale": "step 2: launch the just-installed app",
        },
    ],
})

# Low-confidence fallback for any prompt we don't recognise. Still valid
# JSON — the contusion router rejects this via confidence < 0.6 and
# returns needs_clarification=True to the caller.
_LOW_CONF_JSON = json.dumps({
    "handler_type": "screenshot",
    "args": {},
    "confidence": 0.10,
    "rationale": "mock has no scripted response for this prompt",
})


import re as _re

# The daemon's prompts include a long catalog of handler-type identifiers
# ("screenshot", "app.install_steam", ...) above the actual user instruction.
# Naive substring matching against the WHOLE prompt would false-positive
# (e.g. "do something inscrutable" sees "screenshot" in the catalog).
# So we extract just the user instruction and match against THAT.
#
# Both daemon paths emit the user text on a line of the form:
#   Instruction: 'take a screenshot'           (contusion._route_via_llm)
#   Instruction: "complex multi-step task"     (ai_planner._PROMPT)
# (the former uses repr(), the latter f-string with double quotes).
_INSTRUCTION_RE = _re.compile(r"""Instruction:\s*['"](?P<text>[^'"]*)['"]""")


def _pick_scripted(prompt: str) -> str:
    """Dispatch ONLY on the user-instruction substring of the prompt.

    Falls back to whole-prompt matching if the instruction marker is
    absent (defensive — keeps the mock useful for ad-hoc test prompts).
    """
    if not isinstance(prompt, str):
        return _LOW_CONF_JSON
    m = _INSTRUCTION_RE.search(prompt)
    target = (m.group("text") if m else prompt).lower()
    # Order matters: planner-shaped multi-step is checked first because
    # the multi-step instruction may embed words like "screenshot" if the
    # user composed a multi-step that also takes a screenshot.
    if "complex multi-step" in target:
        return _MULTISTEP_JSON
    if "screenshot" in target:
        return _SCREENSHOT_JSON
    if "install firefox" in target:
        return _INSTALL_FIREFOX_JSON
    return _LOW_CONF_JSON


# ---------------------------------------------------------------------------
# Public async entry points (daemon/llm.py compatibility surface).
# ---------------------------------------------------------------------------

async def generate(
    prompt: str,
    max_tokens: int = 256,
    temperature: float = 0.2,
    timeout: float = 3.0,
    stop: Optional[list] = None,
) -> Optional[str]:
    """Async coroutine returning a scripted JSON string, or None on bad input.

    Signature matches daemon/llm.py:generate() exactly — positional
    prompt + keyword max_tokens/temperature/timeout/stop. Tests that
    assert on call arguments can introspect via unittest.mock wrapping.
    """
    if not isinstance(prompt, str) or not prompt:
        return None
    return _pick_scripted(prompt)


async def query(
    prompt: str,
    max_tokens: int = 512,
    temperature: float = 0.7,
    **kw: Any,
) -> dict:
    """Envelope-style wrapper: returns {"status":"ok","text":<scripted>}.

    Spec shape: accepts (prompt, max_tokens, temperature, **kw) and
    returns a dict, mirroring daemon/llm.py:query(). Kwargs are accepted
    and ignored so the mock doesn't break if a future caller passes
    top_p or similar.
    """
    text = _pick_scripted(prompt)
    return {
        "status": "ok",
        "text": text,
        "usage": {"prompt_tokens": len(prompt) // 4,
                  "completion_tokens": len(text) // 4},
    }


async def analyze_binary(path: str, **kw: Any) -> dict:
    """Fixed advisory for binary_signatures integration tests.

    Always returns advisory="allow" with a canned llm_note so callers
    can smoke-test the endpoint without a real signature DB.
    """
    return {
        "path": path,
        "exists": True,
        "size": 1024,
        "classification": "known",
        "profile_name": "mock-binary",
        "category": "test",
        "engine": "mock",
        "anti_cheat": "none",
        "drm": "none",
        "estimated_compatibility": 1.0,
        "advisory": "allow",
        "llm_note": "mock advisory: harmless test fixture",
        "reason": "mock classifier",
    }


# Shim for daemon/llm.py:query_stream (some callers fall back to it).
async def query_stream(prompt: str, **kw: Any):
    """Minimal async generator yielding one chunk, for API symmetry."""
    yield _pick_scripted(prompt)
