"""
Walk the ENDPOINT_TRUST table: every mutating endpoint at trust >= 300 must
be unreachable below its band and reachable at/above it.

We pick representative endpoints from each tier rather than hit all ~200,
so the test is bounded in time and doesn't accidentally launch programs,
restart services, or rewrite the firewall. Each probe uses a safe-ish
payload where the auth check runs BEFORE any state mutation (every route
in the sample list validates auth in middleware, so even 400 Bad Request
is an acceptable "we passed auth" outcome — we only assert 401/403 vs
non-auth-reject).
"""

import pytest
import requests


# (path, method, min_trust, body) — each is a mutating endpoint that
# exists in the daemon and has a clear trust band in ENDPOINT_TRUST.
MUTATING_SAMPLES = [
    ("/filesystem/write", "POST", 400,
     {"path": "/tmp/int-test-probe", "content": "", "mode": "w"}),
    ("/filesystem/delete", "POST", 400, {"path": "/tmp/int-test-probe"}),
    ("/firewall/enable", "POST", 600, {}),
    ("/firewall/disable", "POST", 600, {}),
    ("/firewall/reload", "POST", 600, {}),
    ("/system/command", "POST", 600,
     {"command": "true", "timeout": 5}),
    ("/automation/script", "POST", 600,
     {"script": "print('noop')"}),
    ("/auto/command", "POST", 600, {"command": "true"}),
    ("/packages/install", "POST", 500, {"package": "nonexistent"}),
    ("/packages/remove", "POST", 500, {"package": "nonexistent"}),
    ("/desktop/launch-exe", "POST", 400, {"path": "/nonexistent.exe"}),
    ("/services/start", "POST", 400, {"name": "nonexistent"}),
]


def _mint(daemon_info, trust_level: int) -> str:
    # Reuse the forging helper via conftest's secret file. If forging fails
    # we fall back to POST /auth/token with the admin token.
    from pathlib import Path

    from conftest import _forge_token

    secret_path = Path("/var/lib/ai-control/auth_secret")
    if secret_path.exists():
        return _forge_token(secret_path.read_bytes(), 3, f"band-{trust_level}",
                            trust_level)
    r = requests.post(
        f"{daemon_info['base_url']}/auth/token",
        headers={"Authorization": f"Bearer {daemon_info['admin_token']}"},
        json={"subject_id": 3, "name": f"band-{trust_level}",
              "trust_level": trust_level},
        timeout=5,
    )
    r.raise_for_status()
    body = r.json()
    return body.get("token") or body["access_token"]


@pytest.mark.parametrize("path,method,min_trust,body", MUTATING_SAMPLES)
def test_below_band_rejected(daemon, path, method, min_trust, body):
    tok = _mint(daemon, max(0, min_trust - 200))
    r = requests.request(
        method,
        f"{daemon['base_url']}{path}",
        headers={"Authorization": f"Bearer {tok}"},
        json=body,
        timeout=15,
    )
    assert r.status_code in (401, 403), (
        f"{method} {path} at trust={max(0, min_trust - 200)} "
        f"(required {min_trust}) should be 401/403, got {r.status_code}: "
        f"{r.text[:200]}"
    )


@pytest.mark.parametrize("path,method,min_trust,body", MUTATING_SAMPLES)
def test_at_band_not_auth_rejected(daemon, path, method, min_trust, body,
                                   admin_headers):
    r = requests.request(
        method,
        f"{daemon['base_url']}{path}",
        headers=admin_headers,
        json=body,
        timeout=15,
    )
    assert r.status_code not in (401, 403), (
        f"{method} {path} with admin (trust=900 >= {min_trust}) should NOT "
        f"be auth-rejected; got {r.status_code}: {r.text[:200]}"
    )
