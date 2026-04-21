"""End-to-end validation of the AI Arch disk installer.

This test boots the live ISO in QEMU against a blank qcow2, drives the
installer via its headless helper, power-cycles, and re-boots from the
installed disk to verify the install was correct and persistent.

It is a thin pytest wrapper around ``scripts/test-install-to-disk.sh``:
the bash harness is the source of truth for the QEMU sequence (serial
logs, cleanup trap, answer-file parsing, boot-counter unit, OVMF
discovery, SSH polling).  The wrapper exists so CI systems that already
run pytest get structured failure reports without having to parse bash.

Markers:
    slow     — takes 10-20 min under TCG, ~5 min with KVM.
    qemu     — requires qemu-system-x86_64, qemu-img, sshpass, scp.
    integration

Skip conditions (all return pytest.skip, not fail):
    * No ISO under ``output/``  — nothing to install from.
    * ``qemu-system-x86_64`` / ``qemu-img`` / ``sshpass`` missing.
    * Harness exits 77: installer binary absent on the ISO.

The harness exit codes feed into the test outcome:
    0   → pass
    1   → fail (verification mismatch)
    2   → error (environment problem, reported as fail but with a distinct
          message so it's easy to tell apart)
    77  → skip

We intentionally stream the bash stdout through to the pytest log so a
CI operator can see which verification failed without digging through
`/tmp/qemu-install-*.log` on the worker.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS = REPO_ROOT / "scripts" / "test-install-to-disk.sh"
ANSWERS = REPO_ROOT / "scripts" / "install-answers.txt"
OUTPUT_DIR = REPO_ROOT / "output"


pytestmark = [
    pytest.mark.slow,
    pytest.mark.qemu,
    pytest.mark.integration,
]


def _iso_present() -> Path | None:
    if not OUTPUT_DIR.exists():
        return None
    for p in sorted(OUTPUT_DIR.glob("*.iso")):
        return p
    return None


def _binaries_present() -> list[str]:
    missing = []
    for b in ("qemu-system-x86_64", "qemu-img", "sshpass", "scp", "ssh"):
        if shutil.which(b) is None:
            missing.append(b)
    return missing


@pytest.fixture(scope="session")
def iso_path() -> Path:
    p = _iso_present()
    if p is None:
        pytest.skip(f"no ISO under {OUTPUT_DIR} — build one with scripts/build-iso.sh")
    return p


@pytest.fixture(scope="session")
def bins_ok() -> None:
    missing = _binaries_present()
    if missing:
        pytest.skip(f"missing required binaries: {', '.join(missing)}")
    if not HARNESS.exists():
        pytest.skip(f"harness script missing: {HARNESS}")
    if not ANSWERS.exists():
        pytest.skip(f"answers file missing: {ANSWERS}")


def _run_harness(preset: str, keep_disk: bool = False) -> int:
    """Run the bash harness and return its exit code.

    stdout and stderr are inherited so pytest captures them into the
    test log.  We convert harness exit code 77 into pytest.skip().
    """
    cmd: list[str] = ["bash", str(HARNESS), f"--preset={preset}"]
    if keep_disk:
        cmd.append("--keep-disk")
    # Let the harness talk to the terminal so interactive CI runs stream
    # live progress; when invoked headlessly pytest's capfd captures it.
    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    proc = subprocess.run(cmd, env=env)
    rc = proc.returncode
    if rc == 77:
        pytest.skip("installer binary not on ISO (harness exit 77)")
    return rc


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
#
# We expose two parameterizations.  Default CI runs only 'minimal' because
# 'full' installs the XFCE desktop stack and doubles pacstrap time.  Devs
# who want the full battery can pass -k full.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("preset", ["minimal"])
def test_install_to_disk_minimal(bins_ok, iso_path, preset, capfd):
    """Minimal preset: base system + AI control daemon, no desktop."""
    rc = _run_harness(preset=preset)
    # rc==2 is an environment error; treat as failure but flag it clearly.
    assert rc == 0, f"installer harness exited {rc} (0=pass, 1=fail, 2=env)"


@pytest.mark.parametrize("preset", ["full"])
def test_install_to_disk_full(bins_ok, iso_path, preset, capfd):
    """Full preset: base + XFCE + Firefox + gaming stack.

    Significantly longer than the minimal run (pacstrap downloads ~2 GB
    instead of ~400 MB).  Skipped by default in CI; run manually via
    ``pytest -m slow -k test_install_to_disk_full``.
    """
    if os.environ.get("AI_ARCH_RUN_FULL_INSTALL") != "1":
        pytest.skip(
            "full-preset install is slow; set AI_ARCH_RUN_FULL_INSTALL=1 to enable"
        )
    rc = _run_harness(preset=preset)
    assert rc == 0, f"installer harness exited {rc}"


def test_harness_and_answers_exist():
    """Cheap sanity check — catches accidental deletion of the harness
    without incurring a 15-minute QEMU cycle."""
    assert HARNESS.is_file(), f"missing: {HARNESS}"
    assert ANSWERS.is_file(), f"missing: {ANSWERS}"
    # Answer file format: at least one expected key present.
    text = ANSWERS.read_text()
    for key in ("hostname=", "username=", "disk=", "bootloader="):
        assert key in text, f"answers file missing required key: {key}"


def test_harness_is_executable_bash_syntax():
    """Lint the harness with ``bash -n`` so syntax errors surface in
    0.1 s instead of 10 min into a QEMU run."""
    if shutil.which("bash") is None:
        pytest.skip("bash not available")
    proc = subprocess.run(
        ["bash", "-n", str(HARNESS)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert proc.returncode == 0, f"bash -n failed: {proc.stderr}"
