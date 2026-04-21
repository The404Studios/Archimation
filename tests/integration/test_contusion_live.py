"""
Contusion live-desktop integration test.

Runs the same battery as `scripts/contusion-desktop-diag.sh` but in pytest
form so it can slot into CI (on a runner with X) or a pre-release manual
gate. Every test skips gracefully if:

  • no DISPLAY / WAYLAND_DISPLAY is set (headless environment);
  • the required external tool (wmctrl / xdotool / brightnessctl / wpctl /
    xclip / scrot) is not installed;
  • the AI daemon is not reachable at the configured host/port.

What each test verifies is the **actual side effect**, not just that the
daemon accepted the phrase. That is the whole point of this file — the
existing `test_contusion.py` validates API contract; this validates the
side-effect pipeline end-to-end.

Run:
    pytest -v tests/integration/test_contusion_live.py

Override host/port:
    CONTUSION_HOST=127.0.0.1 CONTUSION_PORT=8420 pytest ...

Tooling required on the box:
    curl wmctrl xdotool brightnessctl wireplumber xclip scrot xprop
"""

from __future__ import annotations

import json
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


HOST = os.environ.get("CONTUSION_HOST", "127.0.0.1")
PORT = int(os.environ.get("CONTUSION_PORT", "8420"))
BASE = f"http://{HOST}:{PORT}"
SETTLE_S = 0.4

# ---------------------------------------------------------------------------
# Skip gates
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.skipif(
    not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
    reason="no graphical session (DISPLAY / WAYLAND_DISPLAY unset)",
)


def _require(*tools: str) -> None:
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        pytest.skip(f"missing tools: {', '.join(missing)}")


def _run(*cmd: str, timeout: float = 5.0) -> str:
    """Return stdout of a command, '' on failure. Never raises."""
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


# ---------------------------------------------------------------------------
# Daemon + token fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def daemon_up() -> str:
    """Probe the daemon; skip the whole module if it's down."""
    if requests is None:
        pytest.skip("python-requests not installed")
    try:
        r = requests.get(f"{BASE}/health", timeout=3)
    except Exception as e:
        pytest.skip(f"daemon unreachable at {BASE}: {e}")
    if r.status_code != 200:
        pytest.skip(f"daemon /health returned {r.status_code}")
    return BASE


@pytest.fixture(scope="module")
def token_400(daemon_up: str) -> str:
    r = requests.post(
        f"{daemon_up}/auth/token",
        json={"subject_id": 1, "name": "desktop-diag-400",
              "trust_level": 400, "ttl": 600},
        timeout=5,
    )
    if r.status_code != 200:
        pytest.skip(f"could not mint trust-400 token: {r.status_code} {r.text[:120]}")
    tok = r.json().get("token")
    if not tok:
        pytest.skip("token response missing 'token' field")
    yield tok
    # Best-effort revoke.
    try:
        requests.post(
            f"{daemon_up}/auth/revoke",
            headers={"Authorization": f"Bearer {tok}"},
            json={}, timeout=2,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Restore hooks: capture volume + brightness once at module load, restore
# in a finalizer so reruns don't drift.
# ---------------------------------------------------------------------------


def _get_volume() -> str:
    if shutil.which("wpctl") is None:
        return ""
    out = _run("wpctl", "get-volume", "@DEFAULT_AUDIO_SINK@")
    # "Volume: 0.45 [MUTED]"
    for tok in out.split():
        try:
            float(tok)
            return tok
        except ValueError:
            continue
    return ""


def _is_muted() -> bool:
    if shutil.which("wpctl") is None:
        return False
    return "MUTED" in _run("wpctl", "get-volume", "@DEFAULT_AUDIO_SINK@")


def _get_brightness() -> int:
    if shutil.which("brightnessctl") is None:
        return -1
    out = _run("brightnessctl", "get").strip()
    try:
        return int(out.splitlines()[0]) if out else -1
    except Exception:
        return -1


@pytest.fixture(scope="module", autouse=True)
def _restore_system_state():
    orig_vol = _get_volume()
    orig_muted = _is_muted()
    orig_bright = _get_brightness()
    yield
    if orig_vol and shutil.which("wpctl") is not None:
        _run("wpctl", "set-volume", "@DEFAULT_AUDIO_SINK@", orig_vol)
        _run("wpctl", "set-mute", "@DEFAULT_AUDIO_SINK@",
             "1" if orig_muted else "0")
    if orig_bright >= 0 and shutil.which("brightnessctl") is not None:
        _run("brightnessctl", "set", str(orig_bright))


# ---------------------------------------------------------------------------
# Shared helper: POST /contusion/context
# ---------------------------------------------------------------------------


def _post_context(base: str, token: str, phrase: str) -> dict:
    r = requests.post(
        f"{base}/contusion/context",
        headers={"Authorization": f"Bearer {token}"},
        json={"prompt": phrase},
        timeout=8,
    )
    assert r.status_code == 200, f"context returned {r.status_code}: {r.text[:200]}"
    try:
        return r.json()
    except json.JSONDecodeError:
        return {}


def _settle(seconds: float = SETTLE_S) -> None:
    time.sleep(seconds)


# ---------------------------------------------------------------------------
# Audio tests
# ---------------------------------------------------------------------------


def test_audio_volume_up(daemon_up, token_400):
    _require("wpctl")
    # Pre-condition: not muted, not already at 100%.
    if _is_muted():
        _run("wpctl", "set-mute", "@DEFAULT_AUDIO_SINK@", "0")
    before = float(_get_volume() or "0")
    if before >= 0.90:
        _run("wpctl", "set-volume", "@DEFAULT_AUDIO_SINK@", "0.50")
        _settle(0.15)
        before = float(_get_volume() or "0")

    _post_context(daemon_up, token_400, "turn up the volume")
    _settle()
    after = float(_get_volume() or "0")

    assert after > before, f"volume did not increase: {before} -> {after}"


def test_audio_volume_down(daemon_up, token_400):
    _require("wpctl")
    before = float(_get_volume() or "0")
    if before <= 0.10:
        _run("wpctl", "set-volume", "@DEFAULT_AUDIO_SINK@", "0.50")
        _settle(0.15)
        before = float(_get_volume() or "0")

    _post_context(daemon_up, token_400, "turn down the volume")
    _settle()
    after = float(_get_volume() or "0")

    assert after < before, f"volume did not decrease: {before} -> {after}"


def test_audio_mute_toggle(daemon_up, token_400):
    _require("wpctl")
    # Force a known state (unmuted), then ask to mute.
    _run("wpctl", "set-mute", "@DEFAULT_AUDIO_SINK@", "0")
    _settle(0.15)
    assert not _is_muted(), "could not pre-unmute"

    _post_context(daemon_up, token_400, "mute the audio")
    _settle()
    assert _is_muted(), "mute phrase did not mute sink"


# ---------------------------------------------------------------------------
# Brightness tests
# ---------------------------------------------------------------------------


def test_brightness_up(daemon_up, token_400):
    _require("brightnessctl")
    before = _get_brightness()
    if before < 0:
        pytest.skip("no brightness device (no backlight on this machine?)")
    # Head-room: if within 10% of max, drop to 50% first.
    max_out = _run("brightnessctl", "max").strip()
    try:
        max_v = int(max_out)
    except Exception:
        max_v = 0
    if max_v > 0 and before >= max_v * 9 // 10:
        _run("brightnessctl", "set", str(max_v // 2))
        _settle(0.15)
        before = _get_brightness()

    _post_context(daemon_up, token_400, "increase brightness")
    _settle()
    after = _get_brightness()
    assert after > before, f"brightness did not increase: {before} -> {after}"


def test_brightness_down(daemon_up, token_400):
    _require("brightnessctl")
    before = _get_brightness()
    if before < 0:
        pytest.skip("no brightness device")
    if before <= 2:
        max_out = _run("brightnessctl", "max").strip()
        try:
            max_v = int(max_out)
        except Exception:
            max_v = 0
        if max_v > 0:
            _run("brightnessctl", "set", str(max_v // 2))
            _settle(0.15)
            before = _get_brightness()

    _post_context(daemon_up, token_400, "decrease brightness")
    _settle()
    after = _get_brightness()
    assert after < before, f"brightness did not decrease: {before} -> {after}"


# ---------------------------------------------------------------------------
# Workspace switching
# ---------------------------------------------------------------------------


def _current_workspace() -> str:
    if shutil.which("wmctrl") is None:
        return ""
    for line in _run("wmctrl", "-d").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "*":
            return parts[0]
    return ""


def test_workspace_switch(daemon_up, token_400):
    _require("wmctrl")
    total = len([l for l in _run("wmctrl", "-d").splitlines() if l.strip()])
    if total < 2:
        pytest.skip(f"only {total} workspace(s) configured — need >= 2")
    before = _current_workspace()
    target = "0" if before != "0" else "1"
    try:
        _post_context(daemon_up, token_400, f"switch to workspace {int(target)+1}")
        _settle()
        after = _current_workspace()
        assert before != after, f"workspace unchanged: {before} -> {after}"
    finally:
        # Restore.
        if before:
            subprocess.run(["wmctrl", "-s", before],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,
                           check=False)


# ---------------------------------------------------------------------------
# Window state tests — spawn a disposable test window so we don't interfere
# with the operator's real workspace.
# ---------------------------------------------------------------------------


def _spawn_test_window():
    """Return a Popen of a short-lived X client, or None if we can't."""
    if shutil.which("xterm"):
        return subprocess.Popen(
            ["xterm", "-geometry", "80x24+100+100",
             "-title", "ctn-diag-test", "-e", "sleep 30"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if shutil.which("xmessage"):
        return subprocess.Popen(
            ["xmessage", "-center", "-timeout", "30",
             "contusion diag test window"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if shutil.which("xeyes"):
        return subprocess.Popen(
            ["xeyes", "-geometry", "200x200+100+100"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return None


def _find_test_window():
    out = _run("xdotool", "search", "--name", "ctn-diag-test")
    for line in out.splitlines():
        line = line.strip()
        if line.isdigit():
            return line
    return ""


def _wm_state(wid: str) -> str:
    if not wid:
        return ""
    out = _run("xprop", "-id", wid, "_NET_WM_STATE")
    # Format: "_NET_WM_STATE(ATOM) = _NET_WM_STATE_MAXIMIZED_HORZ, ..."
    if "=" in out:
        return out.split("=", 1)[1].strip()
    return ""


@pytest.fixture
def test_window():
    _require("xdotool", "xprop")
    proc = _spawn_test_window()
    if proc is None:
        pytest.skip("no xterm/xmessage/xeyes for spawning a test window")
    _settle(0.5)
    wid = _find_test_window()
    if not wid:
        # Fallback: last window by pid.
        out = _run("xdotool", "search", "--pid", str(proc.pid))
        for line in out.splitlines():
            if line.strip().isdigit():
                wid = line.strip()
                break
    if not wid:
        try:
            proc.terminate()
        except Exception:
            pass
        pytest.skip("could not locate spawned test window")
    subprocess.run(["xdotool", "windowactivate", wid],
                   stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL,
                   check=False)
    _settle(0.15)
    yield wid
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def test_window_maximize(daemon_up, token_400, test_window):
    wid = test_window
    before = _wm_state(wid)
    if "MAXIMIZED" in before.upper():
        pytest.skip("window already maximized by WM at spawn")
    _post_context(daemon_up, token_400, "maximize this window")
    _settle()
    after = _wm_state(wid)
    assert "MAXIMIZED" in after.upper(), \
        f"window not maximized: before='{before}' after='{after}'"


def test_window_minimize(daemon_up, token_400, test_window):
    wid = test_window
    subprocess.run(["xdotool", "windowactivate", wid],
                   stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL,
                   check=False)
    _settle(0.15)
    # Count visible instances before/after.
    before_visible = len([l for l in _run(
        "xdotool", "search", "--name", "ctn-diag-test", "--onlyvisible"
    ).splitlines() if l.strip()])
    _post_context(daemon_up, token_400, "minimize this window")
    _settle()
    after_visible = len([l for l in _run(
        "xdotool", "search", "--name", "ctn-diag-test", "--onlyvisible"
    ).splitlines() if l.strip()])
    hidden = "HIDDEN" in _wm_state(wid).upper()
    assert after_visible < before_visible or hidden, (
        f"window still visible and not HIDDEN: visible {before_visible}->"
        f"{after_visible}, state='{_wm_state(wid)}'"
    )


# ---------------------------------------------------------------------------
# Screenshot
# ---------------------------------------------------------------------------


def test_screenshot(daemon_up, token_400):
    _require("scrot")
    picdir = Path(os.environ.get("XDG_PICTURES_DIR",
                                 str(Path.home() / "Pictures")))
    picdir.mkdir(parents=True, exist_ok=True)

    def count_png() -> int:
        return sum(1 for _ in picdir.rglob("*.png"))

    before = count_png()
    marker = time.time() - 2
    _post_context(daemon_up, token_400, "take a screenshot")
    _settle(0.8)
    after = count_png()
    fresh = [p for p in picdir.rglob("*.png") if p.stat().st_mtime >= marker]
    assert after > before or fresh, (
        f"no new .png in {picdir}: {before}->{after}, fresh={len(fresh)}"
    )


# ---------------------------------------------------------------------------
# Clipboard round-trip
# ---------------------------------------------------------------------------


def test_clipboard_roundtrip(daemon_up, token_400):
    _require("xclip")
    unique = f"ctn-diag-{int(time.time())}-{os.getpid()}"
    # Clear clipboard first.
    p = subprocess.Popen(
        ["xclip", "-selection", "clipboard", "-in"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    p.communicate(input=b"", timeout=2)
    _settle(0.1)

    _post_context(daemon_up, token_400, f"copy '{unique}' to clipboard")
    _settle()
    got = _run("xclip", "-selection", "clipboard", "-out").strip()
    assert unique in got, f"clipboard did not receive token: got='{got[:60]}'"
