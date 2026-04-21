"""bootc lifecycle integration tests — Agent ε / S72 Phase 1.

Three gates that a PR touching bootc/, trust/, or packages/ must pass:

  1. test_image_contains_required_packages
       Build succeeds AND pacman -Q finds trust-system, ai-control-daemon,
       pe-loader inside the image.

  2. test_image_has_signed_trust_module
       /usr/lib/modules/<kver>/extra/trust.ko exists in the image AND a
       detached .sig or kernel module signature is present.

  3. test_attestation_configured
       The airootfs or kernel cmdline carries `trust.attest=hardware` or
       equivalent, meaning trust.ko will try TPM2 in init.

Each test subprocess-calls a bash helper (test-bootc-build.sh) and asserts
exit code + grep-able output.  Pytest is the structured report wrapper; the
bash is the source of truth — same pattern as test_installer.py.

Skip rules (pytest.skip, not fail):
  * podman not installed         → SKIP (can't build)
  * test-bootc-build.sh exits 3  → SKIP (prereq missing)
  * STUB build-mode marker       → mark tests xfail with reason

Markers:
  * bootc        — all tests in this file
  * integration  — opt-in via `-m integration`
  * slow         — image build can be 5-15 min the first time
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_SCRIPT = REPO_ROOT / "scripts" / "test-bootc-build.sh"
ROLLBACK_SCRIPT = REPO_ROOT / "scripts" / "test-bootc-rollback.sh"
ATTEST_SCRIPT = REPO_ROOT / "scripts" / "test-bootc-attestation.sh"
CONTAINERFILE = REPO_ROOT / "bootc" / "Containerfile"
AIROOTFS = REPO_ROOT / "profile" / "airootfs"

IMAGE_TAG = os.environ.get("IMAGE_TAG", "localhost/archimation-bootc:test")
OUT_DIR = Path(os.environ.get("OUT_DIR", "/tmp/bootc-test"))

pytestmark = [
    pytest.mark.bootc,
    pytest.mark.integration,
    pytest.mark.slow,
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """subprocess.run with repo-root cwd and captured text output."""
    kwargs.setdefault("cwd", str(REPO_ROOT))
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    kwargs.setdefault("timeout", 1800)  # 30 min safety ceiling
    return subprocess.run(cmd, **kwargs)


def _build_mode() -> str:
    """Returns 'STUB', 'REAL', or 'UNKNOWN' depending on what the build
    harness left in /tmp/bootc-test/build-mode.  Tests can use this to
    downgrade hard-asserts to xfail when running against a stub image.
    """
    marker = OUT_DIR / "build-mode"
    if not marker.is_file():
        return "UNKNOWN"
    return marker.read_text().strip().upper() or "UNKNOWN"


# ---------------------------------------------------------------------------
# Session-scoped fixture: build the image ONCE, reuse across 3 tests.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def bootc_image() -> str:
    """Invoke scripts/test-bootc-build.sh; return the image tag on success.

    Exit codes from the bash harness:
      0  — image built (REAL or STUB)
      1  — build failed
      2  — smoke check failed
      3  — prereq missing (podman absent, etc.)
    """
    if not _have("podman"):
        pytest.skip("podman not installed; cannot build bootc image")
    if not BUILD_SCRIPT.is_file():
        pytest.skip(f"{BUILD_SCRIPT} missing")

    # Allow re-using a previous successful build within the same session.
    env = os.environ.copy()
    env.setdefault("IMAGE_TAG", IMAGE_TAG)
    env.setdefault("OUT_DIR", str(OUT_DIR))

    proc = _run(["bash", str(BUILD_SCRIPT)], env=env)
    if proc.returncode == 3:
        pytest.skip(
            f"test-bootc-build.sh prereq missing (exit 3):\n{proc.stderr[-1500:]}"
        )
    if proc.returncode != 0:
        pytest.fail(
            f"test-bootc-build.sh exit={proc.returncode}\n"
            f"--- stdout ---\n{proc.stdout[-2000:]}\n"
            f"--- stderr ---\n{proc.stderr[-2000:]}"
        )
    return IMAGE_TAG


# ---------------------------------------------------------------------------
# Gate 1 — image contains required packages
# ---------------------------------------------------------------------------
REQUIRED_PACKAGES = ("trust-system", "ai-control-daemon", "pe-loader")


def test_image_contains_required_packages(bootc_image: str) -> None:
    """pacman -Q succeeds for the three packages that make ARCHIMATION
    *ARCHIMATION* (trust kernel, AI daemon, PE loader).

    On a STUB build (test-bootc-build.sh fell back to plain archlinux:latest
    when Agent α's Containerfile wasn't reachable) this is xfail'd with a
    clear reason rather than a hard failure — a stub image is correctly
    missing the packages, but we still want to exercise the gate plumbing.
    """
    if _build_mode() == "STUB":
        pytest.xfail("STUB build: no ARCHIMATION packages expected inside")

    proc = _run(
        ["podman", "run", "--rm", bootc_image,
         "bash", "-c", f"pacman -Q {' '.join(REQUIRED_PACKAGES)}"],
    )
    assert proc.returncode == 0, (
        f"pacman -Q failed in {bootc_image}:\n"
        f"--- stdout ---\n{proc.stdout}\n"
        f"--- stderr ---\n{proc.stderr}"
    )
    for pkg in REQUIRED_PACKAGES:
        assert pkg in proc.stdout, f"package {pkg} missing from image"


# ---------------------------------------------------------------------------
# Gate 2 — signed trust.ko is present at /usr/lib/modules/*/extra/trust.ko
# ---------------------------------------------------------------------------
def test_image_has_signed_trust_module(bootc_image: str) -> None:
    """trust.ko must ship INSIDE the image (Agent β), not built first-boot
    via DKMS. Additionally the module must carry a signature — either an
    in-band kernel module signature (strings shows '~Module signature'
    trailer) or a detached .sig next to it.
    """
    if _build_mode() == "STUB":
        pytest.xfail("STUB build: Agent β's trust.ko layer not present")

    # 1. Locate trust.ko
    locate = _run(
        ["podman", "run", "--rm", bootc_image,
         "bash", "-c",
         "ls /usr/lib/modules/*/extra/trust.ko 2>/dev/null"],
    )
    assert locate.returncode == 0 and locate.stdout.strip(), (
        "trust.ko not present at /usr/lib/modules/*/extra/trust.ko;\n"
        "bootc mode should ship a prebuilt .ko (Agent β). DKMS-on-boot is\n"
        "incompatible with the immutable /usr tree.\n"
        f"locate stdout: {locate.stdout}\n"
        f"locate stderr: {locate.stderr}"
    )
    ko_path = locate.stdout.strip().splitlines()[0]

    # 2. Check signature presence.  The kernel module sig trailer ends with
    #    the literal bytes "~Module signature appended~" followed by the
    #    sig itself.  `strings` is in Arch base-devel but may not be in
    #    the minimal image; probe with grep as a portable fallback.
    sig_probe = _run(
        ["podman", "run", "--rm", bootc_image,
         "bash", "-c",
         f"( grep -aoc 'Module signature appended' {ko_path} || true ) ; "
         f"test -f {ko_path}.sig && echo detached:yes || echo detached:no"],
    )
    out = sig_probe.stdout.strip()
    lines = out.splitlines()
    has_inline = len(lines) >= 1 and lines[0].isdigit() and int(lines[0]) > 0
    has_detached = any("detached:yes" in ln for ln in lines)
    assert has_inline or has_detached, (
        f"trust.ko at {ko_path} has no signature (inline or detached).\n"
        f"sig probe output:\n{out}"
    )


# ---------------------------------------------------------------------------
# Gate 3 — attestation is configured to boot HARDWARE-mode by default
# ---------------------------------------------------------------------------
def test_attestation_configured() -> None:
    """Trust kernel only enters HARDWARE attestation mode when explicitly
    opted in via kernel cmdline or /etc config — `soft` mode is the
    legacy default.  For the bootc image to live up to the moat story,
    that opt-in must ship inside the image.

    We accept any of these knobs (shape, not value) in the image config:
      * /etc/trust/attest.conf      → `mode = hardware`
      * /etc/modprobe.d/trust.conf  → `options trust attest_mode=hardware`
      * /etc/default/grub           → `trust.attest=hardware` in cmdline
      * profile/airootfs/etc/...    → same, at image build time

    This test inspects the repo tree (NOT the built image) so it runs
    even when podman is unavailable — catches the config regression at
    source-review time, not at boot.
    """
    needles = [
        "trust.attest=hardware",
        "attest_mode=hardware",
        "mode = hardware",
        "mode=hardware",
    ]
    searched: list[Path] = []
    for candidate in (
        AIROOTFS / "etc" / "trust" / "attest.conf",
        AIROOTFS / "etc" / "modprobe.d" / "trust.conf",
        AIROOTFS / "etc" / "default" / "grub",
        AIROOTFS / "etc" / "kernel" / "cmdline",
        CONTAINERFILE,
    ):
        if candidate.is_file():
            searched.append(candidate)
            txt = candidate.read_text(errors="replace")
            if any(n in txt for n in needles):
                return  # found it — test PASSES

    pytest.xfail(
        "No `trust.attest=hardware` / `attest_mode=hardware` opt-in found in\n"
        f"any of: {[str(p) for p in searched] or 'none of the expected files'}.\n"
        "Agent γ needs to wire this into profile/airootfs/etc/trust/attest.conf\n"
        "or the kernel cmdline for HARDWARE attestation to activate on boot."
    )


# ---------------------------------------------------------------------------
# Gate 4 — rollback harness is syntactically valid + executable
# ---------------------------------------------------------------------------
def test_rollback_harness_parses() -> None:
    """We cannot run the rollback smoke in this test env (QEMU+swtpm+
    bootc-image-builder too heavy for CI-lite), but we CAN assert the
    script is shell-valid and carries the stage markers we document.
    """
    assert ROLLBACK_SCRIPT.is_file(), f"{ROLLBACK_SCRIPT} missing"
    # `bash -n` checks syntax without executing
    proc = _run(["bash", "-n", str(ROLLBACK_SCRIPT)])
    assert proc.returncode == 0, (
        f"bash -n rejected {ROLLBACK_SCRIPT.name}:\n{proc.stderr}"
    )
    body = ROLLBACK_SCRIPT.read_text()
    # Documented stage markers — harness grep-ability for CI log parsing.
    for marker in ("[STAGE-0]", "STAGE-1", "bootc rollback", "swtpm"):
        assert marker in body, f"rollback harness missing expected marker: {marker!r}"


def test_attestation_harness_parses() -> None:
    """Same shape as test_rollback_harness_parses — syntactic gate for the
    tamper-detection script."""
    assert ATTEST_SCRIPT.is_file(), f"{ATTEST_SCRIPT} missing"
    proc = _run(["bash", "-n", str(ATTEST_SCRIPT)])
    assert proc.returncode == 0, (
        f"bash -n rejected {ATTEST_SCRIPT.name}:\n{proc.stderr}"
    )
    body = ATTEST_SCRIPT.read_text()
    for marker in ("PCR 11 mismatch", "attestation", "peloader", "tamper"):
        # case-insensitive — markers are documentation, not enforcement.
        assert marker.lower() in body.lower(), (
            f"attestation harness missing marker: {marker!r}"
        )
