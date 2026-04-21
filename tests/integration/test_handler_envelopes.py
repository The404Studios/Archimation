"""
Envelope-shape regression test for `contusion_handlers.HANDLERS`.

Every handler in the registry MUST return a structurally well-formed
envelope when dispatched with empty args, EVEN if it cannot complete
the requested work in the test environment (no compositor, no D-Bus,
no required binary, etc.). "Structurally well-formed" means:

  * the result is a dict
  * the result has a `success` key (bool)
  * if `success is False`, AT LEAST ONE diagnostic field is present and
    truthy: `error`, `missing`, `missing_dependency`, `needs_confirm`,
    `needs_clarification`, or `confirmation_required`. A bare
    `{success: false}` with no diagnostic is a TEST FAILURE.

The destructive set (~25 handlers) is skipped. It mirrors
`scripts/sweep_handlers.py::DESTRUCTIVE` verbatim.

This test runs against the LOCAL source tree -- it imports
contusion_handlers directly and invokes each handler in-process. It
does NOT spin up a daemon. Handlers that shell out to missing tools
should land in their `_missing(...)` branch, which sets `error` and
satisfies the diagnostic requirement.

Hard timeout per handler: 10s (6s for `monitoring.bt_devices` which
has historically hung -- A1 is adding a hard timeout to that handler;
this test verifies it).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Import setup. Mirror conftest.py so this test runs standalone too.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
DAEMON_ROOT = REPO_ROOT / "ai-control" / "daemon"
AI_CONTROL_ROOT = REPO_ROOT / "ai-control"

for _p in (str(DAEMON_ROOT), str(AI_CONTROL_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import contusion_handlers as _ch  # noqa: E402

HANDLERS = _ch.HANDLERS


# ---------------------------------------------------------------------------
# DESTRUCTIVE -- mirror scripts/sweep_handlers.py exactly. If that file
# grows new entries, copy them here too. We deliberately duplicate rather
# than import to keep the test independent of /scripts being on PYTHONPATH.
# ---------------------------------------------------------------------------

DESTRUCTIVE: frozenset[str] = frozenset({
    # power: would reboot/poweroff the test box
    "power.shutdown", "power.reboot", "power.hibernate",
    "power.suspend", "power.logout",
    # service: would break the running daemon if it stops itself
    "service.stop", "service.restart", "service.reload", "service.disable",
    # driver: unloading is rarely safe to blind-fire
    "driver.unload",
    # game.kill: would SIGKILL processes
    "game.kill",
    # workspace: don't delete the live workspace
    "workspace.delete_current",
    # app.install_*: would touch the network and pacman
    "app.install_steam", "app.install_lutris", "app.install_heroic",
    "app.install_proton", "app.install_claude",
    # audio.restart: would kill pipewire mid-test
    "audio.restart",
    # perf.*: changes power profile / loads gamescope / etc -- too disruptive
    "perf.gamescope_off", "perf.gamescope_on",
    "perf.lowlatency_off", "perf.lowlatency_on", "perf.dxvk_clear",
    # system.record: would start a screen recording
    "system.record_start", "system.record_stop",
    # legacy.shell_exec: arbitrary shell -- never blind-fire
    "legacy.shell_exec",
})


# Per-handler timeout overrides (seconds). bt_devices has historically
# wedged on bluetoothctl probes; A1 is adding a hard internal timeout.
# Pin a tight cap here so a regression to "hang forever" fails fast.
_TIMEOUT_OVERRIDES: dict[str, float] = {
    "monitoring.bt_devices": 6.0,
}
_DEFAULT_TIMEOUT = 10.0


# Diagnostic fields that, when truthy, justify success=False.
_DIAGNOSTIC_KEYS = (
    "error",
    "missing",
    "missing_dependency",
    "needs_confirm",
    "needs_clarification",
    "confirmation_required",
)


def _testable_keys() -> list[str]:
    return sorted(set(HANDLERS.keys()) - DESTRUCTIVE)


def _dispatch_sync(handler_type: str) -> dict | None | object:
    """Dispatch the handler with empty args, with a hard timeout.

    Returns the dict the handler produced, or raises asyncio.TimeoutError
    on timeout (which the caller surfaces as a pytest failure).
    """
    fn = HANDLERS[handler_type]
    timeout = _TIMEOUT_OVERRIDES.get(handler_type, _DEFAULT_TIMEOUT)

    async def _run():
        return await asyncio.wait_for(fn({}), timeout=timeout)

    return asyncio.run(_run())


# ---------------------------------------------------------------------------
# Parametrized envelope-shape test (the main gate).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("handler_type", _testable_keys())
def test_handler_envelope_shape(handler_type: str) -> None:
    """Every non-destructive handler returns a well-formed envelope."""
    try:
        result = _dispatch_sync(handler_type)
    except asyncio.TimeoutError:
        pytest.fail(
            f"handler {handler_type!r} hung past "
            f"{_TIMEOUT_OVERRIDES.get(handler_type, _DEFAULT_TIMEOUT)}s; "
            f"add an internal timeout to its body"
        )
    except Exception as e:  # noqa: BLE001
        pytest.fail(
            f"handler {handler_type!r} raised uncaught "
            f"{type(e).__name__}: {e}"
        )

    assert isinstance(result, dict), (
        f"handler {handler_type!r} returned non-dict {type(result).__name__}: "
        f"{result!r}"
    )
    assert "success" in result, (
        f"handler {handler_type!r} envelope missing `success` key; got "
        f"{sorted(result.keys())}"
    )
    assert isinstance(result["success"], bool), (
        f"handler {handler_type!r} `success` must be bool, got "
        f"{type(result['success']).__name__}={result['success']!r}"
    )

    if result["success"] is False:
        diagnostics = {
            k: result.get(k) for k in _DIAGNOSTIC_KEYS if result.get(k)
        }
        assert diagnostics, (
            f"handler {handler_type!r} returned bare success=false with no "
            f"diagnostic field. Envelope keys: {sorted(result.keys())}. "
            f"Add at least one of {_DIAGNOSTIC_KEYS} to the failure path "
            f"(e.g. via _missing()/_bad_arg() or by setting `error=...`)."
        )


# ---------------------------------------------------------------------------
# Manifest sanity: every handler is either destructive (skipped) or tested.
# ---------------------------------------------------------------------------

def test_manifest_accounts_for_every_handler() -> None:
    total = len(HANDLERS)
    destructive_present = sum(1 for k in DESTRUCTIVE if k in HANDLERS)
    tested = len(_testable_keys())

    # The DESTRUCTIVE set may name a handler that no longer exists; we
    # only count entries that intersect HANDLERS so the math closes.
    assert tested + destructive_present == total, (
        f"manifest mismatch: total={total} destructive_present="
        f"{destructive_present} tested={tested} (sum should equal total). "
        f"Did a new handler land that needs DESTRUCTIVE classification?"
    )

    # Soft floor: if HANDLERS shrinks dramatically we want to know.
    assert tested >= 80, (
        f"only {tested} non-destructive handlers? regression suspected; "
        f"total={total}"
    )


# ---------------------------------------------------------------------------
# Negative-regression test for three known-good handlers. Each one shells
# out to an optional binary that is NOT on the test runner; they MUST emit
# a `missing` (or equivalent) diagnostic, never a bare success=false.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "handler_type",
    ["media.play", "system.night_light", "power.screen_off"],
)
def test_known_good_handlers_emit_diagnostic_on_missing_tool(
    handler_type: str,
) -> None:
    """Without the optional binary, the failure path must surface a
    diagnostic field (missing/error/etc) -- not bare success=false."""
    if handler_type not in HANDLERS:
        pytest.skip(f"{handler_type} not in current HANDLERS registry")

    try:
        result = _dispatch_sync(handler_type)
    except asyncio.TimeoutError:
        pytest.fail(f"{handler_type!r} hung")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"{handler_type!r} raised {type(e).__name__}: {e}")

    assert isinstance(result, dict)
    if result.get("success") is True:
        # Tool happens to be installed on the test runner -- that's fine,
        # the envelope-shape test still covers the failure-path contract.
        pytest.skip(
            f"{handler_type} succeeded (tool present); cannot exercise "
            f"missing-tool diagnostic path on this runner"
        )

    diagnostics = {k: result.get(k) for k in _DIAGNOSTIC_KEYS if result.get(k)}
    assert diagnostics, (
        f"{handler_type!r} returned bare success=false with no diagnostic. "
        f"Expected one of {_DIAGNOSTIC_KEYS}; got envelope "
        f"{sorted(result.keys())} = {result!r}"
    )
