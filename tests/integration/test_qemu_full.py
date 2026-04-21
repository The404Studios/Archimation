"""
Pytest wrapper for scripts/test-qemu-extended.sh.

Runs the extended QEMU smoke (sections A..H) end-to-end inside the bash
script, asserting exit 0. Skipped automatically when CI=1 (the smoke takes
~5 minutes due to the Section G 60s memory-leak window plus boot/poll
budget); the CI fast-lane should run unit tests instead and reserve this
for a nightly job.

Skipped when no ISO is found in $ISO_DIR (default: <repo>/output) so
local devs without a built ISO get a clean SKIP rather than a confusing
FAIL.

Session 68: the cortex host-forward port is no longer hardcoded. We ask
the kernel for a free TCP port at fixture time and plumb it through to
the bash harness via $AICONTROL_CORTEX_PORT, so sequential QEMU runs in
the same pytest session never collide on 8421.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import warnings
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "test-qemu-extended.sh"
ISO_DIR = Path(os.environ.get("ISO_DIR", REPO_ROOT / "output"))


def _has_iso() -> bool:
    if not ISO_DIR.is_dir():
        return False
    return any(ISO_DIR.glob("*.iso"))


def _free_port() -> int:
    """Ask the kernel for an unused TCP port (bind :0)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _port_in_use(port: int) -> bool:
    """True if `port` on 127.0.0.1 is currently held by something."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return True
    return False


@pytest.fixture(scope="module")
def qemu_cortex_port() -> int:
    """Pick a free TCP port for the QEMU cortex host-forward (was 8421).

    Module-scoped so every test in this file sees the same port, but
    each test-module invocation gets a fresh allocation — eliminating
    the sequential-run collision that Session 67 deferred.
    """
    return _free_port()


@pytest.fixture(scope="module")
def qemu_ssh_port() -> int:
    """Pick a free TCP port for the QEMU SSH host-forward (was 2222).

    Historically hard-coded at 2222 because the main smoke test uses
    it as a stable ABI and users have it in muscle memory. For the
    extended-smoke pytest path we allocate per-run so back-to-back
    QEMU runs in the same session cannot collide on 2222 either.

    Session 68 A4: pair the cortex dynamic-port fix with SSH so the
    pytest harness is collision-free on *both* forwards.
    """
    return _free_port()


@pytest.mark.skipif(
    os.environ.get("CI", "") == "1",
    reason="CI fast lane skips the 5-minute extended QEMU smoke (nightly job runs it)",
)
@pytest.mark.skipif(
    not SCRIPT.exists(),
    reason=f"extended smoke script not found at {SCRIPT}",
)
@pytest.mark.skipif(
    not _has_iso(),
    reason=f"no ISO in {ISO_DIR} -- run scripts/build-iso.sh first",
)
@pytest.mark.skipif(
    shutil.which("qemu-system-x86_64") is None,
    reason="qemu-system-x86_64 not installed",
)
@pytest.mark.skipif(
    shutil.which("sshpass") is None,
    reason="sshpass not installed (needed by extended smoke)",
)
def test_qemu_extended_smoke(qemu_cortex_port, qemu_ssh_port):
    """Boot ISO, run sections A..H, expect exit 0 (zero FAILs).

    Both host-forward ports (cortex at guest:8420, SSH at guest:22) are
    minted freshly by the kernel via socket bind(:0), so they cannot
    collide with:
      * the session-scoped fake_cortex fixture (which binds 8421)
      * a leftover QEMU from a previous run (either in this pytest
        session or a stray background process)
      * each other
    The bash harness honors the env vars AICONTROL_CORTEX_PORT and
    AICONTROL_QEMU_SSH_PORT; when unset it still falls back to the
    historical 8421/2222 with its own free-port polling path.
    """
    # Both ports were just minted by the kernel via bind(:0) so collision
    # is not expected; still warn (don't skip) if somehow they flipped
    # to in-use between mint and subprocess.run (TOCTOU window).
    for label, port in (("cortex", qemu_cortex_port), ("ssh", qemu_ssh_port)):
        if _port_in_use(port):
            warnings.warn(
                f"port {port} ({label}) already in use between mint and QEMU "
                f"start -- QEMU hostfwd may fail; another QEMU may be running.",
                stacklevel=2,
            )

    env = {
        **os.environ,
        "AICONTROL_CORTEX_PORT": str(qemu_cortex_port),
        "AICONTROL_QEMU_SSH_PORT": str(qemu_ssh_port),
    }

    # Generous timeout: boot (TCG up to 5 min) + sections + 60s G window + slack.
    # Hard cap at 15 min so a hung QEMU doesn't wedge CI forever.
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        capture_output=True,
        text=True,
        timeout=900,
        env=env,
    )
    # Always surface the tail of the smoke output so failures are debuggable
    # without needing to re-run with --capture=no.
    tail = "\n".join((result.stdout or "").splitlines()[-60:])
    err_tail = "\n".join((result.stderr or "").splitlines()[-20:])
    assert result.returncode == 0, (
        f"extended QEMU smoke exited {result.returncode} "
        f"(cortex_port={qemu_cortex_port} ssh_port={qemu_ssh_port})\n"
        f"--- stdout (tail) ---\n{tail}\n"
        f"--- stderr (tail) ---\n{err_tail}"
    )
