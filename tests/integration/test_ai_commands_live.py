"""Pytest wrapper for the live AI-command battery (Session 56, Agent 3).

Boots the freshest ISO under output/ in QEMU and exercises 19 named
checks of /contusion/context dispatch + the ai CLI smoke. The harness
itself lives in ``scripts/test-ai-commands.sh`` so the operator can run
either the bash harness directly or this pytest wrapper.

Skip-gates (the wrapper SKIPs without false-positive failures):
    * QEMU not on PATH (host can't boot the ISO).
    * sshpass not on PATH (the harness mints + uses tokens via SSH).
    * No .iso under ``output/`` -- nothing to boot.
    * The harness file itself is missing.

The actual handler-presence skips happen INSIDE the bash harness so
mid-rebuild Agent 1/2 work doesn't cause CI false-positives.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS = REPO_ROOT / "scripts" / "test-ai-commands.sh"
OUTPUT_DIR = REPO_ROOT / "output"

# 20-minute ceiling: 5 min boot + 30 s settle + 19 curl probes + slack.
HARNESS_TIMEOUT_SEC = 20 * 60


def _newest_iso() -> Path | None:
    if not OUTPUT_DIR.is_dir():
        return None
    isos = [p for p in OUTPUT_DIR.glob("*.iso") if not p.name.endswith(".bak")]
    if not isos:
        return None
    return max(isos, key=lambda p: p.stat().st_mtime)


@pytest.fixture(scope="module")
def harness_path() -> Path:
    if not HARNESS.is_file():
        pytest.skip(f"harness missing: {HARNESS}")
    return HARNESS


@pytest.fixture(scope="module")
def env_ready(harness_path: Path) -> None:
    # Opt-in gate: this test boots a full ISO in QEMU and runs a 19-check
    # battery that takes ~5-20 minutes even on the happy path. Running it
    # unconditionally under `pytest` makes the default test run look like
    # it is hanging. Require an explicit env flag so only deliberate
    # QEMU-smoke invocations pay the cost.
    if not os.environ.get("RUN_LIVE_QEMU_TESTS"):
        pytest.skip(
            "live QEMU battery is opt-in; set RUN_LIVE_QEMU_TESTS=1 "
            "to run (expect 5-20 minute boot+probe cycle)"
        )
    if shutil.which("qemu-system-x86_64") is None:
        pytest.skip("qemu-system-x86_64 not on PATH")
    if shutil.which("sshpass") is None:
        pytest.skip("sshpass not on PATH (token-mint flow needs it)")
    if shutil.which("bsdtar") is None and shutil.which("tar") is None:
        pytest.skip("no tar/bsdtar to extract kernel+initrd")
    iso = _newest_iso()
    if iso is None:
        pytest.skip(f"no .iso under {OUTPUT_DIR}")


def test_live_ai_commands_battery(env_ready, harness_path: Path) -> None:
    """Run scripts/test-ai-commands.sh and assert exit 0 (no FAILs)."""
    env = os.environ.copy()
    # Force C locale so the harness's grep patterns are byte-stable.
    env["LC_ALL"] = "C"
    env.setdefault("BOOT_TIMEOUT", "300")
    env.setdefault("SSHD_WAIT_MAX", "120")
    env.setdefault("SETTLE_SECS", "30")

    proc = subprocess.run(
        ["bash", str(harness_path)],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=HARNESS_TIMEOUT_SEC,
        check=False,
    )
    out = proc.stdout.decode(errors="replace")

    # Always echo the harness output so a failure is debuggable straight
    # from the pytest log (the harness summary lives at the bottom).
    print(out)

    # Locate the RESULT line for a friendlier assertion message.
    result_line = ""
    for line in out.splitlines()[::-1]:
        if "RESULT:" in line:
            result_line = line.strip()
            break

    assert proc.returncode == 0, (
        f"harness exit {proc.returncode}; {result_line or '(no RESULT line)'}\n"
        f"--- last 40 lines ---\n"
        + "\n".join(out.splitlines()[-40:])
    )
