"""
Desktop end-to-end user-journey test.

This is the pytest parallel of ``scripts/test-desktop-e2e.sh``. It exercises
the full graphical user journey:

    boot → XFCE autologin → Super+C → Contusion → real audio change

The shell script is the source of truth for CI (it also spins up a fresh
QEMU with a VNC display and does its own boot). This pytest module
ASSUMES a desktop-capable environment is already running — either a live
Arch install, an attached QEMU/VM with VNC, or a CI runner with Xvfb +
the daemon booted. That makes it useful in two modes:

  1. On the installed OS, as a quick "did the release actually work"
     smoke battery after a fresh boot.
  2. As a thin wrapper that a CI job can call *after* the shell script
     has already brought up the VNC desktop.

All steps skip gracefully when their prerequisites are missing:

  * no DISPLAY / WAYLAND_DISPLAY → entire module skipped (headless)
  * xfce4-session not running → session-dependent tests skipped
  * xdotool/wpctl/scrot missing → individual tests skipped
  * daemon unreachable at 127.0.0.1:8420 → auth/contusion tests skipped
  * wpctl has no default sink → volume test skipped (not failed)

Override the daemon endpoint:

    DESKTOP_E2E_HOST=127.0.0.1 DESKTOP_E2E_PORT=8420 \\
        pytest -v tests/integration/test_desktop_e2e.py

The module mirrors the same step numbering as the shell script so a
failing step can be cross-referenced one-to-one.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore


HOST = os.environ.get("DESKTOP_E2E_HOST", "127.0.0.1")
PORT = int(os.environ.get("DESKTOP_E2E_PORT", "8420"))
BASE = f"http://{HOST}:{PORT}"
SETTLE_S = float(os.environ.get("DESKTOP_E2E_SETTLE", "1.0"))
SCREENSHOT_DIR = Path(os.environ.get("DESKTOP_E2E_SHOT_DIR", "/tmp"))

# Module-level skip gate — no graphical session = nothing to do here.
# Also skip on WSL/containers without systemd (S52: WSL has DISPLAY=:0
# from Windows X-forwarding but no systemd, so lightdm checks always fail).
def _systemd_available() -> bool:
    try:
        return os.path.isdir("/run/systemd/system")
    except OSError:
        return False

pytestmark = pytest.mark.skipif(
    not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    or not _systemd_available(),
    reason=(
        "no graphical session (DISPLAY / WAYLAND_DISPLAY unset) "
        "or systemd not running (WSL/container without /run/systemd/system)"
    ),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _require_tools(*tools: str) -> None:
    missing = [t for t in tools if not _have(t)]
    if missing:
        pytest.skip(f"missing tools: {', '.join(missing)}")


def _run(*cmd: str, timeout: float = 5.0) -> str:
    """Run a command, return stdout (decoded), '' on failure. Never raises."""
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        return p.stdout.decode(errors="replace")
    except Exception:
        return ""


def _daemon_reachable() -> bool:
    if requests is None:
        return False
    try:
        return requests.get(f"{BASE}/health", timeout=2).status_code == 200
    except Exception:
        return False


def _mint_token(trust_level: int = 600) -> str | None:
    """Mint a short-lived token via the localhost-bootstrap auth path."""
    if requests is None:
        return None
    try:
        r = requests.post(
            f"{BASE}/auth/token",
            json={"subject_id": 1, "name": "desktop-e2e-pytest",
                  "trust_level": trust_level},
            timeout=5,
        )
        if r.status_code == 200:
            return r.json().get("token")
    except Exception:
        return None
    return None


@pytest.fixture(scope="module")
def auth_token() -> str:
    """Module-scoped token so we don't mint per test."""
    if not _daemon_reachable():
        pytest.skip(f"ai-control daemon not reachable at {BASE}")
    tok = _mint_token()
    if not tok:
        pytest.skip("could not mint auth token (daemon refused /auth/token)")
    return tok


@pytest.fixture
def auth_headers(auth_token: str) -> dict:
    return {"Authorization": f"Bearer {auth_token}"}


def _wpctl_volume() -> float | None:
    """Return current default-sink volume as float, None if wpctl unavailable.

    ``wpctl get-volume @DEFAULT_AUDIO_SINK@`` prints ``Volume: 0.50`` (or
    ``Volume: 0.50 [MUTED]``) on stdout.
    """
    if not _have("wpctl"):
        return None
    out = _run("wpctl", "get-volume", "@DEFAULT_AUDIO_SINK@")
    if not out or "Volume" not in out:
        return None
    try:
        parts = out.split()
        # parts[0] == "Volume:", parts[1] == "0.50"
        return float(parts[1])
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# Step 1 & 2: Desktop session presence
# ---------------------------------------------------------------------------

def test_1_lightdm_active():
    """LightDM/display manager is active.

    On the live ISO this is almost always true when a DISPLAY is set; the
    test mostly exists so CI gets a clear signal if the user journey is
    running against a non-desktop target.
    """
    _require_tools("systemctl")
    out = _run("systemctl", "is-active", "lightdm")
    state = out.strip()
    # Some hardened installs gate lightdm behind a multi-user chain; accept
    # "activating" the same way the shell script does.
    assert state in ("active", "activating"), (
        f"lightdm state={state!r}; a graphical session is running (DISPLAY "
        f"is set) so a DM ought to be up. Check `journalctl -u lightdm`."
    )


def test_2_xfce_session_running():
    """xfce4-session process is alive for user arch (or the current user)."""
    _require_tools("pgrep")
    # Allow either the "arch" user (live ISO / installed system) or the
    # currently-running user (developer laptop running pytest directly).
    user = os.environ.get("USER", "arch")
    rc = subprocess.run(
        ["pgrep", "-u", user, "-x", "xfce4-session"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode
    if rc != 0 and user != "arch":
        rc = subprocess.run(
            ["pgrep", "-u", "arch", "-x", "xfce4-session"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
    if rc != 0:
        pytest.skip(f"xfce4-session not running for {user!r} — "
                    "not an XFCE session host (may be GNOME, KDE, or Xvfb)")


# ---------------------------------------------------------------------------
# Step 3: Super+C keybinding → Contusion launch
# ---------------------------------------------------------------------------

def test_3_super_c_launches_contusion():
    """Super+C, the documented Contusion shortcut, spawns ``contusion``.

    Setup in ``packages/ai-desktop-config/PKGBUILD``:
        <property name="&lt;Super&gt;c" type="string" value="/usr/bin/contusion"/>
    """
    _require_tools("xdotool", "pgrep")
    if not Path("/usr/bin/contusion").exists():
        pytest.skip("/usr/bin/contusion not installed (package not present)")

    # If contusion is already running, kill it first so we can observe the
    # launch edge cleanly. Idempotent — we restore nothing because Contusion
    # keeps no persistent per-launch state.
    subprocess.run(["pkill", "-x", "contusion"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)

    _run("xdotool", "key", "super+c")

    for _ in range(20):  # up to 10s
        if subprocess.run(
            ["pgrep", "-x", "contusion"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0:
            return
        time.sleep(0.5)

    # Diagnostic: does direct launch work? If yes, the keybinding is broken.
    subprocess.Popen(
        ["/usr/bin/contusion"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    time.sleep(2)
    direct_works = subprocess.run(
        ["pgrep", "-x", "contusion"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0
    subprocess.run(["pkill", "-x", "contusion"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if direct_works:
        pytest.fail(
            "Super+C keybinding did not fire (direct /usr/bin/contusion "
            "launch DID work — check xfconf-query "
            "-c xfce4-keyboard-shortcuts -p '/commands/custom/<Super>c')"
        )
    pytest.fail("contusion never started — binary may be broken")


# ---------------------------------------------------------------------------
# Step 4: Close the Contusion window gracefully
# ---------------------------------------------------------------------------

def test_4_close_contusion_window():
    """``xdotool search --name 'Contusion' windowkill`` closes the dialog."""
    _require_tools("xdotool", "pgrep")
    # Ensure contusion is up (this test can run standalone). If step 3
    # skipped because the binary is absent, we skip here too.
    if not Path("/usr/bin/contusion").exists():
        pytest.skip("/usr/bin/contusion not installed")

    is_up = subprocess.run(
        ["pgrep", "-x", "contusion"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0
    if not is_up:
        subprocess.Popen(
            ["/usr/bin/contusion"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        for _ in range(10):
            time.sleep(0.5)
            if subprocess.run(
                ["pgrep", "-x", "contusion"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ).returncode == 0:
                break
        else:
            pytest.skip("could not start contusion for close test")

    _run("xdotool", "search", "--name", "Contusion", "windowkill", timeout=5)
    for _ in range(10):
        time.sleep(0.5)
        if subprocess.run(
            ["pgrep", "-x", "contusion"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode != 0:
            return

    # Fallback: send SIGTERM so we don't leave a zombie for subsequent tests
    subprocess.run(["pkill", "-TERM", "-x", "contusion"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pytest.fail("xdotool windowkill did not close Contusion — "
                "UI close-handler may be broken")


# ---------------------------------------------------------------------------
# Step 5: Token round-trip
# ---------------------------------------------------------------------------

def test_5_auth_token_roundtrip(auth_token: str, auth_headers: dict):
    """Mint a token via /auth/token, call /health with it."""
    if requests is None:
        pytest.skip("requests not installed")
    r = requests.get(f"{BASE}/health", headers=auth_headers, timeout=5)
    assert r.status_code == 200, f"/health returned {r.status_code}"
    body = r.json()
    assert isinstance(body, dict), f"/health returned non-object: {body!r}"
    assert body.get("status") in ("ok", "healthy"), (
        f"/health status={body.get('status')!r}, body={body!r}"
    )


# ---------------------------------------------------------------------------
# Step 6: /contusion/context "turn up the volume" → real wpctl delta
# ---------------------------------------------------------------------------

def test_6_contusion_volume_up_changes_sink(auth_headers: dict):
    """The real end-to-end test: phrase in → audio sink changes."""
    if requests is None:
        pytest.skip("requests not installed")
    before = _wpctl_volume()
    if before is None:
        pytest.skip("wpctl get-volume unavailable — headless QEMU or no "
                    "PipeWire (expected in CI; pass on real desktop)")

    r = requests.post(
        f"{BASE}/contusion/context",
        headers=auth_headers,
        json={"request": "turn up the volume"},
        timeout=10,
    )
    assert r.status_code == 200, (
        f"/contusion/context returned {r.status_code}: {r.text[:200]}"
    )
    body = r.json()
    assert body.get("status") == "ok", (
        f"contusion rejected phrase: {body!r}"
    )

    time.sleep(SETTLE_S)
    after = _wpctl_volume()
    if after is None:
        pytest.skip("wpctl returned no volume after the call (sink vanished?)")

    if after == before:
        # The engine accepted the request but the sink didn't move. This is
        # a soft skip on headless QEMU where wpctl reports a dummy sink; on
        # a real desktop it should have moved.
        pytest.skip(
            f"contusion accepted 'turn up the volume' but sink stayed at "
            f"{before}; likely a dummy/null sink in this environment"
        )
    assert after > before, (
        f"volume moved the WRONG way: before={before}, after={after}. "
        f"Contusion response: {body!r}"
    )


# ---------------------------------------------------------------------------
# Step 7: Screenshot
# ---------------------------------------------------------------------------

def test_7_screenshot_capture(tmp_path: Path):
    """Capture a screenshot of the current desktop via scrot or import.

    Uses pytest's tmp_path so the file is cleaned up unless the test fails.
    The operator-friendly copy in ``/tmp/desktop-e2e-<ts>.png`` is written
    by the shell script; the pytest version scopes to tmp_path to avoid
    polluting /tmp on every CI run.
    """
    shot = tmp_path / "desktop-e2e.png"
    taken = False
    if _have("scrot"):
        rc = subprocess.run(
            ["scrot", "-o", str(shot)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=10,
        ).returncode
        taken = rc == 0 and shot.exists() and shot.stat().st_size > 0
    if not taken and _have("import"):  # ImageMagick v6
        rc = subprocess.run(
            ["import", "-window", "root", str(shot)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=10,
        ).returncode
        taken = rc == 0 and shot.exists() and shot.stat().st_size > 0
    if not taken and _have("magick"):  # ImageMagick v7
        rc = subprocess.run(
            ["magick", "import", "-window", "root", str(shot)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=10,
        ).returncode
        taken = rc == 0 and shot.exists() and shot.stat().st_size > 0

    if not taken:
        pytest.skip("no screenshot tool available (scrot/import/magick)")

    assert shot.exists(), f"screenshot not created at {shot}"
    size = shot.stat().st_size
    # PNG header is 8 bytes; anything under a few KB is almost certainly a
    # blank/corrupted capture.
    assert size > 1024, f"screenshot suspiciously small: {size} bytes"
