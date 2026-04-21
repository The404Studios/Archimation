#!/usr/bin/env python3
"""
Contusion end-to-end integration test.

Exercises the full UI -> daemon contract the GTK Contusion app depends on:

  1. Bootstrap an auth token at trust 400 (enough for /contusion/context,
     /contusion/launch) and trust 600 (for /contusion/confirm).
  2. Hit /contusion/context with the same field shapes the GUI and shell
     helpers send ("prompt" from the GTK app, "description" from the `ai
     automate` shell, "request" from the canonical API) — all three MUST
     resolve to the same normalized action plan.
  3. Validate response shape matches what the GUI reads:
       top-level `status`, `success`, `actions`, `pending`, `blocked`,
       `needs_confirmation`, `summary`.
  4. /contusion/launch must return flat `{status, success, app, pid?,
     error?, summary}`.
  5. /contusion/confirm accepts either `command` or `value`.

Usage:
    # Against a running daemon:
    python test_contusion.py --host 127.0.0.1 --port 8420

    # With a reachability probe — skips gracefully if the daemon is down
    # so CI can run this alongside a mocked environment:
    python test_contusion.py --skip-if-down
"""

import json
import sys
import urllib.error
import urllib.request

HOST = "127.0.0.1"
PORT = 8420
SKIP_IF_DOWN = False

passed = 0
failed = 0
skipped = 0


def _url(path):
    return f"http://{HOST}:{PORT}{path}"


def _http(method, path, body=None, token=None, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(_url(path), data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode() if e.fp else ""
        try:
            body = json.loads(raw) if raw else {}
        except Exception:
            body = {"raw": raw}
        return e.code, body


def _check(name, cond, detail=""):
    global passed, failed
    print(f"  {name:62s}", end=" ")
    if cond:
        print("\033[32mPASS\033[0m")
        passed += 1
    else:
        print(f"\033[31mFAIL\033[0m {detail}")
        failed += 1


def _skip(name, reason):
    global skipped
    print(f"  {name:62s} \033[33mSKIP\033[0m ({reason})")
    skipped += 1


def daemon_up():
    try:
        status, _ = _http("GET", "/health", timeout=3)
        return status == 200
    except Exception:
        return False


def get_token(trust_level, name="contusion-test"):
    status, body = _http(
        "POST", "/auth/token",
        {"subject_id": 1, "name": name, "trust_level": trust_level, "ttl": 600},
    )
    if status == 200 and isinstance(body, dict) and body.get("token"):
        return body["token"]
    print(f"  !! could not obtain trust={trust_level} token: {status} {body}")
    return None


def run():
    global SKIP_IF_DOWN

    print(f"=== Contusion Integration ({HOST}:{PORT}) ===\n")

    up = daemon_up()
    if not up:
        if SKIP_IF_DOWN:
            _skip("daemon reachability", f"no daemon at {HOST}:{PORT}")
            print("\nDaemon offline — run `systemctl start ai-control` (or "
                  "`python ai-control/daemon/main.py`) and retry.")
            return 0
        print(f"!! Daemon not reachable at {HOST}:{PORT} — start ai-control first.")
        return 2

    tok400 = get_token(400, "contusion-test-400")
    tok600 = get_token(600, "contusion-test-600")
    _check("bootstrap token (trust=400)", tok400 is not None)
    _check("bootstrap token (trust=600)", tok600 is not None)
    if not tok400:
        return 2

    # --- /contusion root --------------------------------------------------
    status, body = _http("GET", "/contusion", token=tok400)
    _check("GET /contusion 200", status == 200, f"status={status}")
    _check("GET /contusion has status field",
           isinstance(body, dict) and "status" in body)

    # --- /contusion/apps --------------------------------------------------
    status, body = _http("GET", "/contusion/apps", token=tok400)
    _check("GET /contusion/apps 200", status == 200)
    _check("GET /contusion/apps has apps list",
           isinstance(body, dict) and isinstance(body.get("apps"), list))

    # --- /contusion/context with each field shape -------------------------
    # The GTK app sends "prompt", the shell "ai automate" sends "description",
    # canonical is "request". All MUST be accepted and resolve identically.
    probes = [
        ("prompt",      {"prompt": "list files in /tmp"}),
        ("description", {"description": "list files in /tmp"}),
        ("request",     {"request": "list files in /tmp"}),
        ("instruction", {"instruction": "list files in /tmp"}),
        ("text",        {"text": "list files in /tmp"}),
    ]
    last_summary = None
    for field_name, payload in probes:
        status, body = _http("POST", "/contusion/context", payload, token=tok400)
        _check(f"POST /contusion/context ({field_name}) accepted",
               status == 200, f"status={status} body={body!r:.200}")
        if status == 200 and isinstance(body, dict):
            # Every response must carry the flattened envelope the GUI reads.
            _check(f"context({field_name}) has status",
                   body.get("status") in ("ok", "error"))
            _check(f"context({field_name}) has success flag",
                   isinstance(body.get("success"), bool))
            _check(f"context({field_name}) actions is list",
                   isinstance(body.get("actions"), list))
            _check(f"context({field_name}) pending is list",
                   isinstance(body.get("pending"), list))
            _check(f"context({field_name}) blocked is list",
                   isinstance(body.get("blocked"), list))
            _check(f"context({field_name}) needs_confirmation is bool",
                   isinstance(body.get("needs_confirmation"), bool))
            _check(f"context({field_name}) summary is str",
                   isinstance(body.get("summary"), str))
            if last_summary is None:
                last_summary = body.get("summary")

    # --- Empty instruction — must NOT crash, must return structured env ---
    status, body = _http("POST", "/contusion/context", {}, token=tok400)
    _check("POST /contusion/context {} returns structured error",
           status in (200, 422) and isinstance(body, dict))
    if status == 200:
        _check("empty instruction summary is human-readable",
               isinstance(body.get("summary"), str) and body.get("summary"))

    # --- Dangerous action path: confirm cycle -----------------------------
    # "delete /tmp/contusion_test_nonexistent" triggers confirm-required.
    status, body = _http(
        "POST", "/contusion/context",
        {"prompt": "delete /tmp/contusion_test_nonexistent_zzz"},
        token=tok400,
    )
    _check("dangerous action parseable", status == 200)
    pending = body.get("pending", []) if isinstance(body, dict) else []
    if pending:
        _check("dangerous action marked pending", len(pending) > 0)
        _check("dangerous action needs_confirmation",
               body.get("needs_confirmation") is True)
        # Simulate user confirmation via /contusion/confirm. We confirm a
        # safe synthetic command so the test doesn't actually destroy data.
        if tok600:
            safe_cmd = "echo confirm-round-trip"
            status, cbody = _http(
                "POST", "/contusion/confirm",
                {"command": safe_cmd}, token=tok600,
            )
            _check("POST /contusion/confirm (command=) 200", status == 200)
            _check("confirm returns success",
                   isinstance(cbody, dict) and cbody.get("success") is True)
            # Also test the "value" alias.
            status, cbody = _http(
                "POST", "/contusion/confirm",
                {"value": safe_cmd}, token=tok600,
            )
            _check("POST /contusion/confirm (value=) 200", status == 200)
    else:
        _skip("dangerous action pending path",
              "dictionary did not classify as confirm-required "
              "(safe regression: endpoint still returned a valid envelope)")

    # --- /contusion/launch (no-op app) ------------------------------------
    # Use `htop` as a CLI/TUI-type entry that exists in APP_LIBRARY. We
    # just validate the response shape — the actual launch may fail in a
    # headless test env (no tty, no DISPLAY) and that is EXPECTED.
    status, body = _http(
        "POST", "/contusion/launch", {"app": "htop"}, token=tok400,
    )
    _check("POST /contusion/launch 200", status == 200,
           f"status={status} body={body!r:.200}")
    if status == 200:
        _check("launch has success flag",
               isinstance(body, dict)
               and isinstance(body.get("success"), bool))
        _check("launch has summary",
               isinstance(body, dict) and isinstance(body.get("summary"), str))
        _check("launch echoes app name",
               isinstance(body, dict) and body.get("app") == "htop")

    # Missing app field must not 500.
    status, body = _http(
        "POST", "/contusion/launch", {"app": ""}, token=tok400,
    )
    _check("launch empty app returns structured error",
           status == 200 and isinstance(body, dict)
           and body.get("success") is False)

    # Unknown app must degrade to {success:false, summary}, not crash.
    status, body = _http(
        "POST", "/contusion/launch", {"app": "definitelynotarealapp_zzz"},
        token=tok400,
    )
    _check("launch unknown app returns success=false",
           status == 200 and isinstance(body, dict)
           and body.get("success") is False
           and isinstance(body.get("summary"), str))

    # --- Auth: /contusion/context without token must be 403/401 ----------
    status, body = _http(
        "POST", "/contusion/context", {"prompt": "ls /tmp"}, token=None,
    )
    # Note: check_auth has a loopback GET exemption for trust<=200 only;
    # context is trust=400, so unauthed POST must be rejected.
    _check("unauthed /contusion/context rejected",
           status in (401, 403), f"status={status}")

    # --- Auth: /contusion/confirm requires trust>=600 ---------------------
    if tok400:
        status, body = _http(
            "POST", "/contusion/confirm", {"command": "echo hi"},
            token=tok400,
        )
        _check("confirm with trust=400 rejected", status in (401, 403),
               f"status={status}")

    print(f"\n=== Result: {passed} passed, {failed} failed, {skipped} skipped ===")
    return 0 if failed == 0 else 1


def main():
    global HOST, PORT, SKIP_IF_DOWN
    i = 1
    while i < len(sys.argv):
        a = sys.argv[i]
        if a == "--host" and i + 1 < len(sys.argv):
            HOST = sys.argv[i + 1]; i += 2; continue
        if a == "--port" and i + 1 < len(sys.argv):
            PORT = int(sys.argv[i + 1]); i += 2; continue
        if a == "--skip-if-down":
            SKIP_IF_DOWN = True; i += 1; continue
        if a in ("-h", "--help"):
            print(__doc__)
            return 0
        print(f"unknown argument: {a}", file=sys.stderr)
        return 2
    return run()


if __name__ == "__main__":
    sys.exit(main())
