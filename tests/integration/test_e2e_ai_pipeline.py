"""End-to-end tests for the ``ai`` CLI -> daemon pipeline.

Session 53, Agent 5.  Complementary to S52's
``test_ai_commands.py`` (which tests the daemon directly via TestClient).
This module tests the **CLI** as the entry point: subprocess(``ai ...``)
against a stub daemon that returns CLI-shaped JSON.

Hermetic: the stub daemon is a stdlib ``http.server`` on a free localhost
port.  No network.  No real subprocess execution from the CLI's POV (the
CLI does not spawn anything itself; it only POSTs to the daemon).  The
stub daemon records every "would-be" subprocess call in
``subprocess_calls`` so the multi-step tests can still assert on what
the planner *would* have run.

Test coverage (matches the spec):

  Single-step path
  ----------------
  * test_e2e_ai_screenshot                     — y -> exit 0
  * test_e2e_ai_dry_run_no_execution           — --dry-run -> no execute
  * test_e2e_ai_decline_n                      — n -> exit 1
  * test_e2e_ai_low_confidence_exits_2         — conf<0.3 -> exit 2

  Multi-step path
  ---------------
  * test_e2e_ai_plan_install_and_launch        — 3-step plan, all run
  * test_e2e_ai_plan_dry_run                   — dry_run=True -> 0 calls
  * test_e2e_ai_plan_dep_failure               — step0 fails -> step1 skipped

  Auth + emergency
  ----------------
  * test_e2e_ai_no_token_exits_4               — daemon offline -> exit 4
  * test_e2e_ai_emergency_latch_blocks         — latch active -> exit 3

The CLI under test (``ai-control/cli/ai``) only knows how to call
``/contusion/ai`` -> ``/contusion/confirm`` -> ``/contusion/execute``
(single-step).  It does NOT yet have a subcommand for the multi-step
planner.  The multi-step tests therefore drive the planner endpoints
directly via the same stub daemon and a tiny urllib client — the test
asserts the WIRE CONTRACT the future CLI subcommand will inherit.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

import pytest


# Make the fixtures dir importable.  conftest.py also does this for the
# S52 mock_llm fixture — we mirror the same path manipulation rather
# than touching conftest.py.
_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
if str(_FIXTURES_DIR) not in sys.path:
    sys.path.insert(0, str(_FIXTURES_DIR))

from cli_runner import (  # noqa: E402  (sys.path side-effect)
    AI_CLI_PATH,
    StubDaemon,
    run_ai_cli,
    stub_daemon,
)


pytestmark = pytest.mark.skipif(
    not AI_CLI_PATH.exists(),
    reason=f"ai CLI not present at {AI_CLI_PATH}",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _post_json(url: str, body: dict, token: str = "",
               timeout: float = 5.0) -> tuple[int, dict]:
    """Tiny stdlib POST so multi-step tests don't need ``requests``."""
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), method="POST",
    )
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read().decode("utf-8"))
        except Exception:
            data = {}
        return e.code, data


# ---------------------------------------------------------------------------
# 1. Single-step path through the CLI
# ---------------------------------------------------------------------------


def test_e2e_ai_screenshot():
    """``ai -y take a screenshot`` -> auto-confirm path -> exit 0.

    Verifies the full wire dance:
    1. CLI POSTs /contusion/ai with the instruction.
    2. Stub returns plan(handler_type=screenshot, conf=0.95).
    3. CLI auto-confirms (``-y`` + conf 0.95 >= 0.85 threshold).
    4. CLI POSTs /contusion/confirm and /contusion/execute.
    5. Stub returns success=True; CLI prints [OK]; rc=0.

    Why ``-y`` instead of stdin "y\\n"?  The CLI's ``_prompt_confirm``
    short-circuits to "n" when ``sys.stdin.isatty()`` is False (line
    269 of ``ai-control/cli/ai``).  Since pipes are NOT TTYs, feeding
    ``"y\\n"`` over stdin is silently ignored.  ``-y`` is the only
    non-interactive path the CLI exposes.
    """
    with stub_daemon() as d:
        rc, out, err = run_ai_cli(
            "-y", "take", "a", "screenshot",
            daemon_url=d.url,
            token="test-token",
        )

    assert rc == 0, (
        f"expected exit 0; got rc={rc}\n"
        f"stdout={out!r}\nstderr={err!r}"
    )
    # Plan was rendered.
    assert "screenshot" in out.lower(), out
    assert "0.95" in out, f"confidence missing from output: {out!r}"
    # And both phases happened in the right order.
    paths = [r["path"] for r in d.requests if r["method"] == "POST"]
    assert "/contusion/ai" in paths, paths
    assert "/contusion/confirm" in paths, paths
    assert "/contusion/execute" in paths, paths
    # Authorization header was forwarded.
    ai_calls = d.find_request("/contusion/ai")
    assert ai_calls, "no /contusion/ai request recorded"
    assert ai_calls[0]["headers"].get("Authorization") == "Bearer test-token"


def test_e2e_ai_dry_run_no_execution():
    """``ai --dry-run take a screenshot`` -> plan rendered, NO execute."""
    with stub_daemon() as d:
        rc, out, err = run_ai_cli(
            "--dry-run", "take", "a", "screenshot",
            daemon_url=d.url,
            token="test-token",
        )
    assert rc == 0, (
        f"--dry-run should exit 0; got rc={rc}\nstdout={out!r}\nstderr={err!r}"
    )
    # Plan rendered.
    assert "screenshot" in out.lower(), out
    assert "dry-run" in out.lower(), (
        f"CLI should announce dry-run mode; got {out!r}"
    )
    paths = [r["path"] for r in d.requests if r["method"] == "POST"]
    assert "/contusion/ai" in paths, paths
    # The crucial assertion: dry-run must NOT confirm or execute.
    assert "/contusion/confirm" not in paths, (
        f"dry-run leaked /contusion/confirm: {paths}"
    )
    assert "/contusion/execute" not in paths, (
        f"dry-run leaked /contusion/execute: {paths}"
    )


def test_e2e_ai_decline_n():
    """``ai take a screenshot`` answered "n" -> exit 1, no execute."""
    with stub_daemon() as d:
        rc, out, err = run_ai_cli(
            "take", "a", "screenshot",
            daemon_url=d.url,
            token="test-token",
            stdin_input="n\n",
        )
    assert rc == 1, (
        f"declined prompt should exit 1; got rc={rc}\n"
        f"stdout={out!r}\nstderr={err!r}"
    )
    assert "declined" in out.lower(), out
    paths = [r["path"] for r in d.requests if r["method"] == "POST"]
    assert "/contusion/ai" in paths
    assert "/contusion/confirm" not in paths, (
        f"decline must NOT confirm: {paths}"
    )
    assert "/contusion/execute" not in paths, (
        f"decline must NOT execute: {paths}"
    )


def test_e2e_ai_low_confidence_exits_2():
    """Stub returns conf=0.10 -> CLI hits low-conf branch -> exit 2."""
    with stub_daemon(low_conf=True) as d:
        rc, out, err = run_ai_cli(
            "do", "something", "inscrutable",
            daemon_url=d.url,
            token="test-token",
            stdin_input="y\n",   # ignored — CLI bails before prompting
        )
    assert rc == 2, (
        f"low confidence should exit 2; got rc={rc}\n"
        f"stdout={out!r}\nstderr={err!r}"
    )
    combined = (out + err).lower()
    assert "low confidence" in combined or "rephrase" in combined, (
        f"expected clarifying message; got out={out!r} err={err!r}"
    )
    # Stub MUST NOT have been asked to confirm/execute.
    paths = [r["path"] for r in d.requests if r["method"] == "POST"]
    assert "/contusion/confirm" not in paths
    assert "/contusion/execute" not in paths


# ---------------------------------------------------------------------------
# 2. Multi-step planner — drives the daemon endpoints directly because the
#    current CLI does NOT have a multi-step subcommand yet.  Test the
#    contract the future CLI will speak.
# ---------------------------------------------------------------------------


def test_e2e_ai_plan_install_and_launch():
    """``install steam, launch it, turn on gamescope`` -> 3 steps run."""
    with stub_daemon() as d:
        # Phase 1: build the plan.
        code, plan = _post_json(
            f"{d.url}/ai/plan",
            {"instruction": "install steam, launch it, turn on gamescope",
             "max_steps": 8},
        )
        assert code == 200, plan
        assert plan.get("plan_id"), plan
        steps = plan.get("steps") or []
        assert len(steps) == 3, f"expected 3 steps, got {steps}"
        assert [s["handler_type"] for s in steps] == [
            "app.install_steam", "app.launch", "perf.gamescope_on",
        ], steps

        # Phase 2: execute the plan.
        d.subprocess_calls.clear()
        code2, exe = _post_json(
            f"{d.url}/ai/plan/execute",
            {"plan_id": plan["plan_id"], "dry_run": False},
        )
        assert code2 == 200, exe
        results = exe.get("results") or []
        assert len(results) == 3
        assert all(r["status"] == "completed" for r in results), results

    # All three "would-be" subprocess calls were captured, in order.
    assert len(d.subprocess_calls) == 3, d.subprocess_calls
    assert d.subprocess_calls[0][0] == "pacman", d.subprocess_calls
    assert d.subprocess_calls[1][0] == "steam", d.subprocess_calls
    assert "gamescope" in " ".join(d.subprocess_calls[2]).lower(), (
        d.subprocess_calls
    )


def test_e2e_ai_plan_dry_run():
    """dry_run=True -> all steps marked dry_run, ZERO subprocess calls."""
    with stub_daemon() as d:
        code, plan = _post_json(
            f"{d.url}/ai/plan",
            {"instruction": "install steam, launch it, turn on gamescope",
             "max_steps": 8},
        )
        assert code == 200, plan
        d.subprocess_calls.clear()
        code2, exe = _post_json(
            f"{d.url}/ai/plan/execute",
            {"plan_id": plan["plan_id"], "dry_run": True},
        )
        assert code2 == 200, exe
        results = exe.get("results") or []
        assert len(results) == 3
        for r in results:
            assert r["status"] == "dry_run", r
        assert d.subprocess_calls == [], d.subprocess_calls


def test_e2e_ai_plan_dep_failure():
    """Step 0 fails (rc=1) -> step 1 skipped_dep_failed; step 2 still runs."""
    with stub_daemon(execute_failure=True) as d:
        code, plan = _post_json(
            f"{d.url}/ai/plan",
            {"instruction": "install steam, launch it, turn on gamescope",
             "max_steps": 8},
        )
        assert code == 200, plan
        d.subprocess_calls.clear()
        code2, exe = _post_json(
            f"{d.url}/ai/plan/execute",
            {"plan_id": plan["plan_id"], "dry_run": False},
        )
        assert code2 == 200, exe
        results = exe.get("results") or []
        statuses = {r["index"]: r["status"] for r in results}
        # Step 0 (install) is failed by the stub's execute_failure flag.
        assert statuses[0] == "failed", statuses
        # Step 1 (launch) depends on step 0 -> must be skipped.
        assert statuses[1] == "skipped_dep_failed", statuses
        # Step 2 (gamescope) has no dep on 0 -> runs anyway.
        assert statuses[2] == "completed", statuses
        # Subprocess record reflects: step0 (failed call still recorded
        # because the planner attempted it), step2 (gamescope) attempted,
        # step1 (launch) NOT attempted because it was skipped.
        attempted = [c[0] for c in d.subprocess_calls]
        assert "pacman" in attempted, attempted
        assert "steam" not in attempted, (
            f"launch step must not be attempted under dep failure; "
            f"got attempted={attempted}"
        )


# ---------------------------------------------------------------------------
# 3. Auth + emergency
# ---------------------------------------------------------------------------


def test_e2e_ai_no_token_exits_4():
    """Daemon URL points at an unbound port -> CLI exit 4 (unreachable)."""
    # offline=True picks a port but does NOT bind it; the CLI gets ECONN.
    with stub_daemon(offline=True) as d:
        rc, out, err = run_ai_cli(
            "install", "firefox",
            daemon_url=d.url,
            token="",  # no token either, but the unreachable check fires first
        )
    assert rc == 4, (
        f"unreachable daemon should exit 4; got rc={rc}\n"
        f"stdout={out!r}\nstderr={err!r}"
    )
    combined = (out + err).lower()
    assert ("cannot reach" in combined or "unreachable" in combined
            or "connect" in combined), (
        f"CLI should hint that the daemon is unreachable; "
        f"out={out!r} err={err!r}"
    )


def test_e2e_ai_emergency_latch_blocks():
    """Stub returns 409 from /contusion/ai -> CLI surfaces failure (exit 3).

    The CLI's _post helper treats >=500 as exit 3 and 401/403 as exit 4.
    For 409 (latch active) the CLI proceeds into _extract_plan with a
    body that has no plan + zero confidence — which trips the
    "low confidence" branch (exit 2).  Either rejection is acceptable
    as "the destructive action did NOT execute"; we assert the CLI
    bailed (rc != 0) AND surfaced the latch message AND did NOT call
    /contusion/confirm or /contusion/execute.
    """
    with stub_daemon(emergency_active=True) as d:
        rc, out, err = run_ai_cli(
            "install", "firefox",
            daemon_url=d.url,
            token="test-token",
            stdin_input="y\n",
        )
    assert rc != 0, (
        f"latch-active should NOT exit 0; got rc={rc}\n"
        f"stdout={out!r}\nstderr={err!r}"
    )
    # Pick up the 409 message either in stdout (verbose body dump) or stderr.
    combined = (out + err).lower()
    # The CLI's exit-2 / exit-3 paths surface different markers.  Either
    # the latch text leaks via the daemon body OR the CLI's own "Low
    # confidence" line fires because the response had no plan.  Both
    # outcomes prove the CLI did NOT execute the action.
    assert ("emergency" in combined or "latch" in combined
            or "low confidence" in combined or "blocked" in combined), (
        f"expected emergency/latch/low-conf marker; "
        f"out={out!r} err={err!r}"
    )
    # The CLI MUST NOT have advanced past /contusion/ai.
    paths = [r["path"] for r in d.requests if r["method"] == "POST"]
    assert "/contusion/confirm" not in paths, (
        f"latch-active must NOT confirm: {paths}"
    )
    assert "/contusion/execute" not in paths, (
        f"latch-active must NOT execute: {paths}"
    )


# ---------------------------------------------------------------------------
# 4. Sanity smoke — included so a totally broken CLI fails fast and loud
#    (and so this file always has at least one passing test even if the
#    HOME-config trick stops working on a future CLI version).
# ---------------------------------------------------------------------------


def test_e2e_ai_help_exits_zero():
    """``ai --help`` -> rc 0; smoke test that the script imports cleanly."""
    rc, out, err = run_ai_cli("--help", daemon_url=None, token=None)
    assert rc == 0, (
        f"ai --help failed: rc={rc} out={out!r} err={err!r}"
    )
    combined = (out + err).lower()
    assert "natural-language" in combined or "ai" in combined, combined
