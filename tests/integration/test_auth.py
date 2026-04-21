"""
Auth regression tests. Session 41 found that a token with trust_level=0
could hit /system/command (which requires 600) because check_auth fell
through to a kernel-trust-observer branch that never fires for API
clients. These tests pin the fix.
"""

import requests


def test_health_no_auth(daemon):
    r = requests.get(f"{daemon['base_url']}/health", timeout=5)
    assert r.status_code == 200


def test_admin_hits_system_command(daemon, admin_headers):
    r = requests.post(
        f"{daemon['base_url']}/system/command",
        json={"command": "true", "timeout": 5},
        headers=admin_headers,
        timeout=15,
    )
    assert r.status_code == 200, r.text


def test_low_trust_blocked_on_system_command(daemon, low_headers):
    r = requests.post(
        f"{daemon['base_url']}/system/command",
        json={"command": "true", "timeout": 5},
        headers=low_headers,
        timeout=15,
    )
    assert r.status_code in (401, 403), (
        f"trust_level=0 token should be rejected by /system/command, "
        f"got {r.status_code}: {r.text}"
    )


def test_no_token_blocked_on_system_command(daemon):
    # 127.0.0.1 GETs <= 200 are allowed tokenless, but POST /system/command
    # is trust 600 and must NOT ride the localhost_read exemption.
    r = requests.post(
        f"{daemon['base_url']}/system/command",
        json={"command": "true", "timeout": 5},
        timeout=15,
    )
    assert r.status_code in (401, 403), (
        f"tokenless localhost should NOT access /system/command; "
        f"got {r.status_code}"
    )


def test_malformed_token_rejected(daemon):
    r = requests.post(
        f"{daemon['base_url']}/system/command",
        json={"command": "true"},
        headers={"Authorization": "Bearer not.a.real.token"},
        timeout=10,
    )
    assert r.status_code in (401, 403)
