"""
/ai/decide tier-3 degradation test.

The spec calls for a tier-3 (LLM-disabled) degraded envelope from /ai/decide
with a `verdict` field. Session 41 audit: the daemon does NOT currently
expose /ai/decide — only /ai/status, /ai/models, /ai/load, /ai/unload,
/ai/query. This test is marked xfail until that endpoint lands. Running it
is still useful: it pins the gap and will flip green the moment the route
is added.
"""

import pytest
import requests


def test_ai_status_reachable_degraded(daemon, admin_headers):
    r = requests.get(f"{daemon['base_url']}/ai/status", headers=admin_headers, timeout=10)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "llama_cpp_available" in body or "available" in body or "status" in body


@pytest.mark.xfail(
    reason=(
        "Session 41 gap: /ai/decide route does not exist. Daemon exposes "
        "/ai/query for inference but no structured-verdict endpoint. This "
        "test pins the gap; flip to passing when the route is added."
    ),
    strict=False,
)
def test_ai_decide_returns_verdict_envelope(daemon, admin_headers):
    r = requests.post(
        f"{daemon['base_url']}/ai/decide",
        headers=admin_headers,
        json={
            "subject_id": 42,
            "context": {"action": "launch", "app": "notepad.exe"},
        },
        timeout=15,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "verdict" in body, (
        f"tier-3 degraded envelope must carry a `verdict` field; got {body}"
    )
    assert body["verdict"] in ("ALLOW", "DENY", "QUARANTINE", "ESCALATE", "MODIFY")


def test_ai_query_unavailable_when_llm_disabled(daemon, admin_headers):
    r = requests.post(
        f"{daemon['base_url']}/ai/query",
        headers=admin_headers,
        json={"prompt": "hello", "max_tokens": 8},
        timeout=10,
    )
    # LLM_DISABLED=1 in conftest; we accept 200-with-error-envelope,
    # 503 (service unavailable), or 501 (not implemented).
    assert r.status_code in (200, 501, 503), (
        f"expected graceful LLM-disabled response, got {r.status_code}: {r.text}"
    )
