"""
Functional tests for AI commands — end-to-end through the daemon.

Session 52, Agent Z. The user wants AI commands to actually WORK
("instruction -> plan -> execute -> result observed"), not just be
endpoint-reachable. This module exercises the full path:

  POST /contusion/ai          -> route via mock LLM, return proposal
  POST /contusion/ai (auto)   -> route + execute, capture subprocess call
  POST /ai/plan               -> decompose multi-step instruction
  POST /ai/plan/execute       -> dispatch each step's handler, capture calls
  ai (CLI)                    -> --help works; missing daemon -> exit 4

All HTTP endpoints are exercised in-process via FastAPI TestClient. The
LLM module is replaced with fixtures/mock_llm.py before create_app()
runs (see conftest::mock_llm_app). subprocess egress is replaced with a
recorder that captures every call without executing it. A tiny stdlib
HTTP server on 127.0.0.1:8421 stands in for the cortex (so the daemon's
emergency-latch + autonomy probes get real responses).

Hermetic: no network, no real subprocess, no real LLM. Every test
should pass on a fresh `pacman -S python-pytest python-aiohttp`
install with httpx + fastapi already on disk.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
AI_CLI_PATH = REPO_ROOT / "ai-control" / "cli" / "ai"


# ---------------------------------------------------------------------------
# Helper: shorthand for authenticated POST.
# ---------------------------------------------------------------------------

def _post(client, path: str, body: dict, token: str | None = None,
          timeout: float = 10.0):
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return client.post(path, json=body, headers=headers, timeout=timeout)


# ---------------------------------------------------------------------------
# 1. Single-step AI fallback (Agent 1's S51 work — /contusion/ai)
# ---------------------------------------------------------------------------

def test_contusion_ai_endpoint_screenshot(test_client, auth_token,
                                          subprocess_recorder):
    """Mock LLM maps "take a screenshot" -> handler_type=screenshot."""
    r = _post(test_client, "/contusion/ai",
              {"instruction": "take a screenshot", "auto_confirm": False},
              token=auth_token)
    assert r.status_code == 200, r.text
    body = r.json()
    # Daemon wraps the LLM's proposal in success+needs_confirmation.
    assert body.get("success") is True, f"unexpected envelope: {body}"
    assert body.get("needs_confirmation") is True
    proposal = body.get("proposal") or {}
    results = proposal.get("results") or []
    assert results, f"no LLM results returned: {body}"
    r0 = results[0]
    assert r0.get("handler_type") == "screenshot"
    assert float(r0.get("confidence", 0)) >= 0.6
    # auto_confirm was False -> the daemon must NOT have executed anything.
    assert subprocess_recorder.calls == [], (
        f"expected no subprocess calls (auto_confirm=False); "
        f"got {subprocess_recorder.calls}"
    )


def test_contusion_ai_endpoint_low_confidence(test_client, auth_token,
                                              subprocess_recorder):
    """Mock LLM returns confidence=0.10 for unknown prompts -> clarification."""
    r = _post(test_client, "/contusion/ai",
              {"instruction": "do something inscrutable",
               "auto_confirm": False},
              token=auth_token)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("needs_clarification") is True, (
        f"expected needs_clarification on low-conf, got {body}"
    )
    # No execution attempt either.
    assert subprocess_recorder.calls == []


def test_contusion_ai_auto_confirm_high_conf(test_client, auth_token,
                                             subprocess_recorder):
    """auto_confirm=True + conf>=0.85 -> daemon executes, scrot captured."""
    r = _post(test_client, "/contusion/ai",
              {"instruction": "take a screenshot now please",
               "auto_confirm": True},
              token=auth_token)
    assert r.status_code == 200, r.text
    body = r.json()
    # Auto-confirm should have flipped executed=True. We tolerate either
    # success=True (handler returned ok) or success=False (handler hit
    # an env-specific issue) — what we MUST see is that subprocess was
    # invoked. That's the "result observed" the spec demands.
    assert body.get("executed") is True, (
        f"auto_confirm with conf>=0.85 should execute; got {body}"
    )
    # The screenshot handler eventually calls scrot via _run_exec ->
    # asyncio.create_subprocess_exec, which the recorder captures.
    scrot_calls = subprocess_recorder.find("scrot")
    assert scrot_calls, (
        f"expected at least one scrot subprocess; got "
        f"{[c.get('argv') for c in subprocess_recorder.calls]}"
    )


# ---------------------------------------------------------------------------
# 2. Multi-step planner (Agent 3's S51 work — /ai/plan + /ai/plan/execute)
# ---------------------------------------------------------------------------

def _make_plan(client, token, instruction="complex multi-step task"):
    r = _post(client, "/ai/plan",
              {"instruction": instruction, "max_steps": 8},
              token=token)
    return r


def test_ai_plan_decomposes_multistep(test_client, auth_token):
    """/ai/plan returns 2 steps with depends_on chain step1->step0."""
    r = _make_plan(test_client, auth_token)
    assert r.status_code == 200, r.text
    plan = r.json()
    assert plan.get("plan_id"), f"no plan_id in {plan}"
    steps = plan.get("steps") or []
    assert len(steps) == 2, f"expected 2 steps, got {len(steps)}: {steps}"
    # Step 0: install_steam, no deps.
    assert steps[0]["index"] == 0
    assert steps[0]["handler_type"] == "app.install_steam"
    assert steps[0]["depends_on"] == []
    # Step 1: launch, depends on step 0.
    assert steps[1]["index"] == 1
    assert steps[1]["handler_type"] == "app.launch"
    assert steps[1]["depends_on"] == [0]


def test_ai_plan_execute_dry_run(test_client, auth_token, subprocess_recorder):
    """dry_run=True -> all steps marked dry_run, no subprocess fires."""
    r = _make_plan(test_client, auth_token)
    assert r.status_code == 200, r.text
    plan_id = r.json()["plan_id"]
    subprocess_recorder.reset()  # in case planning itself spawned anything

    r2 = _post(test_client, "/ai/plan/execute",
               {"plan_id": plan_id, "dry_run": True},
               token=auth_token)
    assert r2.status_code == 200, r2.text
    body = r2.json()
    results = body.get("results") or []
    assert len(results) == 2
    for step in results:
        assert step["status"] == "dry_run", f"step {step}"
    # The most important assertion: dry_run must NOT execute.
    assert subprocess_recorder.calls == [], (
        f"dry_run leaked subprocess calls: {subprocess_recorder.calls}"
    )


def test_ai_plan_execute_real_run(test_client, auth_token, subprocess_recorder):
    """dry_run=False -> both steps' commands hit subprocess recorder."""
    r = _make_plan(test_client, auth_token)
    assert r.status_code == 200, r.text
    plan_id = r.json()["plan_id"]
    subprocess_recorder.reset()
    subprocess_recorder.returncode = 0  # both steps succeed

    r2 = _post(test_client, "/ai/plan/execute",
               {"plan_id": plan_id, "dry_run": False},
               token=auth_token, timeout=30)
    assert r2.status_code == 200, r2.text
    body = r2.json()
    # Step 0 (app.install_steam) -> pacman -S steam
    pacman_calls = subprocess_recorder.find("pacman")
    assert pacman_calls, (
        f"step 0 should have invoked pacman; recorder: "
        f"{[c.get('argv') for c in subprocess_recorder.calls]}"
    )
    # Step 1 (app.launch with name=steam) -> create_subprocess_exec("steam",...)
    steam_calls = [c for c in subprocess_recorder.calls
                   if c.get("argv") and c["argv"][0] == "steam"]
    assert steam_calls, (
        f"step 1 should have launched steam; recorder: "
        f"{[c.get('argv') for c in subprocess_recorder.calls]}"
    )
    # And the planner should have reported both as completed.
    assert body.get("completed", 0) >= 2, (
        f"expected 2 completed steps, body={body}"
    )


def test_ai_plan_step_failure_propagates(test_client, auth_token,
                                         subprocess_recorder):
    """Step 0 fails (rc=1) -> step 1 marked skipped_dep_failed."""
    r = _make_plan(test_client, auth_token)
    assert r.status_code == 200, r.text
    plan_id = r.json()["plan_id"]
    subprocess_recorder.reset()
    subprocess_recorder.returncode = 1   # every spawn returns failure

    r2 = _post(test_client, "/ai/plan/execute",
               {"plan_id": plan_id, "dry_run": False},
               token=auth_token, timeout=30)
    assert r2.status_code == 200, r2.text
    body = r2.json()
    results = body.get("results") or []
    assert len(results) == 2, f"expected 2 step results, got {results}"
    statuses = {r["index"]: r["status"] for r in results}
    assert statuses[0] == "failed", f"step 0 status: {statuses}"
    assert statuses[1] == "skipped_dep_failed", (
        f"step 1 should propagate failure; got {statuses}"
    )
    # Step 1's subprocess MUST NOT have been called.
    steam_calls = [c for c in subprocess_recorder.calls
                   if c.get("argv") and c["argv"][0] == "steam"]
    assert not steam_calls, (
        f"step 1 launched steam despite dep failure: {steam_calls}"
    )


def test_ai_plan_expired_returns_404(test_client, auth_token, monkeypatch):
    """Fast-forward TTL beyond 15 min -> /ai/plan/execute returns 404."""
    r = _make_plan(test_client, auth_token)
    assert r.status_code == 200, r.text
    plan_id = r.json()["plan_id"]

    # Reach into the planner and manually expire the plan by rewriting
    # its expires_at to one second ago. The planner's _prune_expired
    # then drops it on the next execute call.
    import api_server as _api
    planner = _api._ai_planner
    assert planner is not None
    plan = planner._active_plans.get(plan_id)
    assert plan is not None
    # Subtract two seconds from expires_at to land safely in the past.
    from datetime import datetime, timedelta, timezone
    plan["expires_at"] = (datetime.now(timezone.utc)
                          - timedelta(seconds=2)).isoformat()

    r2 = _post(test_client, "/ai/plan/execute",
               {"plan_id": plan_id, "dry_run": False},
               token=auth_token)
    assert r2.status_code == 404, (
        f"expired plan should 404, got {r2.status_code}: {r2.text}"
    )
    body = r2.json()
    assert "expired" in str(body).lower() or "not found" in str(body).lower()


def test_ai_plan_lru_eviction(test_client, auth_token):
    """Create 33 plans -> cap=32 -> oldest plan_id no longer resolves."""
    plan_ids: list[str] = []
    for i in range(33):
        r = _make_plan(test_client, auth_token,
                       instruction=f"complex multi-step #{i}")
        assert r.status_code == 200, (i, r.text)
        plan_ids.append(r.json()["plan_id"])

    # The very first plan should have been LRU-evicted.
    r2 = _post(test_client, "/ai/plan/execute",
               {"plan_id": plan_ids[0], "dry_run": True},
               token=auth_token)
    assert r2.status_code == 404, (
        f"oldest plan should have been LRU-evicted; got "
        f"{r2.status_code}: {r2.text}"
    )

    # The most recent plan still resolves.
    r3 = _post(test_client, "/ai/plan/execute",
               {"plan_id": plan_ids[-1], "dry_run": True},
               token=auth_token)
    assert r3.status_code == 200, r3.text


# ---------------------------------------------------------------------------
# 3. Emergency latch + auth
# ---------------------------------------------------------------------------

def test_contusion_ai_blocked_by_latch(test_client, auth_token, fake_cortex,
                                       subprocess_recorder):
    """Cortex /emergency/status returns active=True -> /contusion/ai 409."""
    # Flip the fake cortex BEFORE the request. The daemon caches latch
    # state for 100 ms; we issue a single call so cache TTL is moot.
    fake_cortex.emergency_active = True
    try:
        r = _post(test_client, "/contusion/ai",
                  {"instruction": "take a screenshot", "auto_confirm": False},
                  token=auth_token)
        # 409 = latch active (per _enforce_emergency_latch). FastAPI may
        # also surface 503 if the cortex probe wedges; both are acceptable
        # rejections of a destructive command under latch.
        assert r.status_code in (409, 503), (
            f"expected 409 (latch active) or 503 (probe failed); "
            f"got {r.status_code}: {r.text}"
        )
        # And no subprocess fired.
        assert subprocess_recorder.calls == []
    finally:
        fake_cortex.emergency_active = False


def test_contusion_ai_requires_auth_above_user(test_client, subprocess_recorder):
    """No bearer token -> /contusion/ai 401/403 (TRUST_INTERACT required)."""
    r = _post(test_client, "/contusion/ai",
              {"instruction": "take a screenshot", "auto_confirm": False},
              token=None)
    # TRUST_INTERACT (200) > TRUST_USER (100), so localhost-read exemption
    # in auth.py does NOT apply to POST. Daemon should reject.
    assert r.status_code in (401, 403), (
        f"missing token should 401/403 a TRUST_INTERACT POST; "
        f"got {r.status_code}: {r.text}"
    )
    assert subprocess_recorder.calls == []


# ---------------------------------------------------------------------------
# 4. `ai` CLI (Agent 2's S51 work)
# ---------------------------------------------------------------------------

def test_ai_cli_help_exits_zero():
    """`ai --help` is the simplest smoke test that the script imports."""
    if not AI_CLI_PATH.exists():
        pytest.skip(f"ai CLI not at {AI_CLI_PATH}")
    proc = subprocess.run(
        [sys.executable, str(AI_CLI_PATH), "--help"],
        capture_output=True, text=True, timeout=15,
    )
    assert proc.returncode == 0, (
        f"ai --help failed (rc={proc.returncode}): "
        f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
    # Spot-check the help text — confirms argparse built the parser.
    out = (proc.stdout + proc.stderr).lower()
    assert "natural-language" in out or "ai" in out, (
        f"help text suspect: {proc.stdout!r}"
    )


def test_ai_cli_no_daemon_exits_4():
    """`ai <task>` with daemon URL pointing at a closed port -> exit 4."""
    if not AI_CLI_PATH.exists():
        pytest.skip(f"ai CLI not at {AI_CLI_PATH}")
    # Pick a port we're confident no daemon is on. 65530 is high enough
    # to dodge ephemeral collisions but well below 65535.
    bogus_url = "http://127.0.0.1:65530"

    # The CLI reads its config from ~/.ai/config.toml; we isolate that
    # by writing a temp config and pointing HOME at a tmpdir.
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        ai_dir = Path(td) / ".ai"
        ai_dir.mkdir()
        (ai_dir / "config.toml").write_text(
            f'daemon_url = "{bogus_url}"\nauth_token = ""\n'
        )
        env = os.environ.copy()
        env["HOME"] = td
        env["USERPROFILE"] = td  # Windows fallback
        env["NO_COLOR"] = "1"
        proc = subprocess.run(
            [sys.executable, str(AI_CLI_PATH), "take", "a", "screenshot"],
            capture_output=True, text=True, env=env, timeout=15,
        )
    # Per ai CLI docstring: "4  daemon unreachable".
    assert proc.returncode == 4, (
        f"daemon-unreachable expected exit 4; got rc={proc.returncode}\n"
        f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
    )
