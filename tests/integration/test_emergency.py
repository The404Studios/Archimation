"""
Emergency-flag tests. The cortex writes /var/lib/ai-control/emergency.flag;
the daemon is supposed to refuse destructive ops (at minimum kill_process)
while it's set. This test xfails if the daemon does NOT yet check the flag
(Session 41 audit: the flag currently gates only the cortex itself; the
daemon's /system/kill does not consult it).
"""

from pathlib import Path

import pytest
import requests

EMERGENCY_FILE = Path("/var/lib/ai-control/emergency.flag")


def _set_emergency(text: str = "integration-test") -> bool:
    try:
        EMERGENCY_FILE.parent.mkdir(parents=True, exist_ok=True)
        EMERGENCY_FILE.write_text(text)
        return True
    except PermissionError:
        return False


def _clear_emergency() -> None:
    try:
        EMERGENCY_FILE.unlink()
    except FileNotFoundError:
        pass
    except PermissionError:
        pass


@pytest.fixture
def maybe_emergency():
    already = EMERGENCY_FILE.exists()
    prev = EMERGENCY_FILE.read_text() if already else None
    yield
    if already and prev is not None:
        try:
            EMERGENCY_FILE.write_text(prev)
        except PermissionError:
            pass
    else:
        _clear_emergency()


def test_kill_self_pid_always_refused(daemon, admin_headers):
    import os
    r = requests.post(
        f"{daemon['base_url']}/system/kill/{os.getpid()}",
        headers=admin_headers,
        timeout=10,
    )
    assert r.status_code == 200
    body = r.json()
    assert body.get("success") is False, (
        "kill of caller's pid should be refused; got {body}"
    )


@pytest.mark.xfail(
    reason=(
        "Session 41 audit: daemon's /system/kill/{pid} does not consult "
        "EMERGENCY_FILE. The cortex owns the latch; the daemon needs to "
        "share it. This test pins the gap."
    ),
    strict=False,
)
def test_emergency_blocks_kill(daemon, admin_headers, maybe_emergency):
    if not _set_emergency("integration-test"):
        pytest.skip("cannot write emergency flag (need root or passwordless sudo)")
    try:
        sentinel_pid = 999_999_998
        r = requests.post(
            f"{daemon['base_url']}/system/kill/{sentinel_pid}",
            headers=admin_headers,
            timeout=10,
        )
        assert r.status_code in (409, 503), (
            f"emergency latch should refuse kills, got {r.status_code}"
        )
    finally:
        _clear_emergency()


def test_clear_emergency_restores_ops(daemon, admin_headers, maybe_emergency):
    _clear_emergency()
    r = requests.get(f"{daemon['base_url']}/health", timeout=5)
    assert r.status_code == 200
