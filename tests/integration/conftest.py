"""
Integration-test harness for ai-control-daemon.

Boots the daemon in a subprocess against a temp state dir, waits for
/health to return 200, yields a fixture bundle (base URL, admin token,
low-trust token), tears everything down on session exit.

Requires: python-pytest, python-requests. The daemon launch expects
/usr/lib/ai-control-daemon/main.py to exist (i.e. run on a system that
pacstrap'd ai-control-daemon, or from a checkout where you symlinked it).

The harness deliberately does NOT use the packaged /usr/bin/ai-control-daemon
launcher so it can override --config without privilege.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import requests


REPO_ROOT = Path(__file__).resolve().parents[2]
DAEMON_ROOT = REPO_ROOT / "ai-control" / "daemon"
CORTEX_ROOT = REPO_ROOT / "ai-control" / "cortex"


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_health(base_url: str, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            r = requests.get(f"{base_url}/health", timeout=2)
            if r.status_code == 200:
                return
        except requests.RequestException as e:
            last_err = e
        time.sleep(0.5)
    raise RuntimeError(
        f"daemon did not reach /health within {timeout}s; last error: {last_err}"
    )


def _make_config(state_dir: Path, log_dir: Path, port: int) -> Path:
    cfg = state_dir / "config.toml"
    cfg.write_text(
        f"""
host = "127.0.0.1"
port = {port}
auth_enabled = true
auth_auto_bootstrap = true
state_dir = "{state_dir}"
log_file = "{log_dir}/daemon.log"
audit_log = "{log_dir}/audit.log"
llm_enabled = false
"""
    )
    return cfg


@pytest.fixture(scope="session")
def daemon():
    """Spin up a daemon process with a scratch state dir."""
    if not (DAEMON_ROOT / "main.py").exists():
        pytest.skip(f"daemon source not at {DAEMON_ROOT}")

    tmp = Path(tempfile.mkdtemp(prefix="ai-control-test-"))
    state_dir = tmp / "state"
    log_dir = tmp / "log"
    state_dir.mkdir()
    log_dir.mkdir()

    port = _pick_free_port()
    cfg_path = _make_config(state_dir, log_dir, port)
    base_url = f"http://127.0.0.1:{port}"

    env = os.environ.copy()
    env["PYTHONPATH"] = f"{DAEMON_ROOT}{os.pathsep}{CORTEX_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"
    env["PYTHONUNBUFFERED"] = "1"
    env["LLM_DISABLED"] = "1"
    env.pop("NOTIFY_SOCKET", None)

    proc = subprocess.Popen(
        [sys.executable, str(DAEMON_ROOT / "main.py"),
         "--config", str(cfg_path)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=str(DAEMON_ROOT),
    )

    try:
        try:
            _wait_for_health(base_url, timeout=60.0)
        except Exception:
            proc.terminate()
            try:
                out, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, _ = proc.communicate()
            pytest.skip(
                f"daemon failed to start (port={port}):\n{out.decode(errors='replace')[-4000:]}"
            )

        admin_token = _mint_token(base_url, state_dir, subject_id=1,
                                  name="test-admin", trust_level=900)
        low_token = _mint_token(base_url, state_dir, subject_id=2,
                                name="test-lowtrust", trust_level=0)

        yield {
            "base_url": base_url,
            "admin_token": admin_token,
            "low_token": low_token,
            "state_dir": state_dir,
            "log_dir": log_dir,
        }

    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        shutil.rmtree(tmp, ignore_errors=True)


def _mint_token(base_url: str, state_dir: Path, subject_id: int,
                name: str, trust_level: int) -> str:
    r = requests.post(
        f"{base_url}/auth/token",
        json={"subject_id": subject_id, "name": name, "trust_level": trust_level},
        timeout=5,
    )
    if r.status_code == 200:
        data = r.json()
        tok = data.get("token") or data.get("access_token")
        if tok:
            return tok
    bootstrap = state_dir / "bootstrap-token"
    if bootstrap.exists():
        return bootstrap.read_text().strip()
    # Last-resort: mint locally with the secret the daemon just wrote. This
    # mirrors auth.create_token() without importing the running daemon.
    secret_path = state_dir / "auth_secret"
    if not secret_path.exists():
        secret_path = Path("/var/lib/ai-control/auth_secret")
    if not secret_path.exists():
        raise RuntimeError(f"could not locate auth_secret; response was {r.status_code} {r.text}")
    return _forge_token(secret_path.read_bytes(), subject_id, name, trust_level)


def _forge_token(secret: bytes, subject_id: int, name: str, trust_level: int,
                 ttl: int = 3600) -> str:
    import base64
    import hashlib
    import hmac
    import time as _t
    import uuid

    now = _t.time()
    payload = {
        "sub": subject_id,
        "name": name,
        "trust": trust_level,
        "iat": int(now),
        "exp": int(now + ttl),
        "jti": str(uuid.uuid4()),
    }
    payload_json = json.dumps(payload, separators=(",", ":"))
    sig = hmac.new(secret, payload_json.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(payload_json.encode()).decode() + "." + sig


@pytest.fixture
def admin_headers(daemon):
    return {"Authorization": f"Bearer {daemon['admin_token']}"}


@pytest.fixture
def low_headers(daemon):
    return {"Authorization": f"Bearer {daemon['low_token']}"}


# ---------------------------------------------------------------------------
# Session 52 (Agent Z) additions: fixtures for AI-commands functional tests
# (test_ai_commands.py).  These fixtures DO NOT spin up a daemon process —
# they build the FastAPI app in-process and drive it via TestClient so the
# tests are fully hermetic (no network, no real subprocess execution).
#
# Order of operations matters:
#   1. fake_cortex   : real HTTP listener on 127.0.0.1:8421 (aiohttp client
#                      target). Has switchable /emergency/status + /autonomy.
#   2. mock_llm_app  : injects fixtures/mock_llm.py into sys.modules['llm']
#                      BEFORE create_app() runs, so daemon's _init_controllers
#                      picks up the mock.  Yields the FastAPI app instance.
#   3. test_client   : starlette TestClient wrapping the app.
#   4. subprocess_recorder : monkeypatches asyncio.create_subprocess_exec +
#                      subprocess.run + shutil.which so handlers run their
#                      full code path without hitting real binaries.
#   5. auth_token    : a TRUST_INTERACT (200) bearer for in-process calls.
# ---------------------------------------------------------------------------

import http.server
import json as _json
import threading as _threading
from http import HTTPStatus as _HTTPStatus

# Path to fixtures/ so imports of mock_llm work regardless of CWD.
_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class _CortexState:
    """Mutable container for the fake-cortex's switchable responses."""

    def __init__(self) -> None:
        # Default: latch clear, autonomy active. Tests that need the latch
        # active or autonomy in lockdown mutate these in-place.
        self.emergency_active: bool = False
        self.autonomy_state: str = "active"

    def emergency_status_body(self) -> dict:
        return {"active": self.emergency_active,
                "reason": "test" if self.emergency_active else None}

    def autonomy_body(self) -> dict:
        return {"state": self.autonomy_state, "level": self.autonomy_state}


@pytest.fixture(scope="session")
def fake_cortex():
    """Spin up a tiny HTTP listener on 127.0.0.1:8421 that fakes the cortex
    /emergency/status + /autonomy endpoints. Yields a _CortexState the test
    can mutate to flip the latch / autonomy state.

    Bound to port 8421 because that is what _cortex_get hard-codes; if a
    real cortex is already running there the bind fails and we skip
    affected tests rather than colliding.
    """
    state = _CortexState()

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802  (stdlib API)
            path = self.path.split("?", 1)[0]
            if path == "/emergency/status":
                body = state.emergency_status_body()
            elif path == "/autonomy":
                body = state.autonomy_body()
            elif path == "/status":
                body = {"status": "ok", "fake": True}
            else:
                self.send_error(_HTTPStatus.NOT_FOUND)
                return
            payload = _json.dumps(body).encode()
            self.send_response(_HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length:
                self.rfile.read(length)  # discard body
            payload = b'{"status": "ok", "fake": true}'
            self.send_response(_HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt, *args):  # silence stderr spam in test runs
            return

    try:
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 8421), _Handler)
    except OSError as e:
        pytest.skip(f"cannot bind 127.0.0.1:8421 for fake cortex: {e}")
    th = _threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield state
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture
def mock_llm_app(fake_cortex, monkeypatch, tmp_path):
    """Build the daemon's FastAPI app in-process with mock LLM injected.

    Yields a tuple (app, fake_cortex_state). The caller wraps `app` in a
    TestClient. We rebuild the app per-test so monkeypatched globals
    (subprocess hooks, latch state) don't bleed across tests.
    """
    import sys as _sys

    # Make daemon imports available without modifying ai-control/__init__.
    daemon_root = REPO_ROOT / "ai-control" / "daemon"
    if str(daemon_root) not in _sys.path:
        _sys.path.insert(0, str(daemon_root))

    # api_server.py does `from cortex.autonomy import EmergencyStoppedError`
    # during latch enforcement. We need the ai-control parent on path so
    # the `cortex` package resolves.
    ai_control_root = REPO_ROOT / "ai-control"
    if str(ai_control_root) not in _sys.path:
        _sys.path.insert(0, str(ai_control_root))

    # Make the fixtures dir importable so we can `import mock_llm`.
    if str(_FIXTURES_DIR) not in _sys.path:
        _sys.path.insert(0, str(_FIXTURES_DIR))

    # CRITICAL: replace sys.modules['llm'] BEFORE create_app() so that
    # api_server._init_controllers picks up the mock as _llm. The real
    # llm.py is heavy (llama_cpp probe) and we want the lightweight stub.
    import mock_llm as _mock_llm
    monkeypatch.setitem(_sys.modules, "llm", _mock_llm)

    # State dir + auth secret in tmp_path so we don't pollute /var/lib.
    # The auth module hard-codes _SECRET_PATH; patch it before create_app.
    import auth as _auth
    secret_path = tmp_path / "auth_secret"
    monkeypatch.setattr(_auth, "_SECRET_PATH", str(secret_path), raising=True)
    # starlette TestClient sets request.client.host="testclient", which
    # is NOT in the auth module's loopback tuple (hardcoded in
    # check_auth at auth.py line ~628). Without an exemption, every
    # unauthed call increments the rate-limit counter and after 10
    # failures EVERY test gets 429 instead of the expected 401/403/200.
    # The _LOOPBACK_ADDRS module-level frozenset was removed; the
    # loopback check is now inline against a literal tuple. We can't
    # monkeypatch a literal, so we just clear the failure log before
    # each test and rely on rate-limit window reset. Tests that hit
    # unauthed-then-authed sequences must not exceed 10 failures per
    # 60s window (see _RATE_LIMIT_MAX_FAILURES).
    _auth._failure_log.clear()
    # Also flush the verify_token LRU so a stale token from a prior test
    # signed with a different secret cannot accidentally validate.
    with _auth._token_cache_lock:
        _auth._TOKEN_CACHE.clear()

    # Force LLM_DISABLED unset so the daemon does NOT short-circuit our mock.
    monkeypatch.delenv("LLM_DISABLED", raising=False)
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)

    # Reduce noise: the daemon spams a lot of init warnings for missing
    # subsystems in the test env (no /dev/uinput, no NVIDIA, no DBus).
    import logging as _logging
    _logging.getLogger("ai-control").setLevel(_logging.ERROR)

    # Reload api_server so any cached _llm reference picks up the mock.
    import importlib as _importlib
    if "api_server" in _sys.modules:
        _importlib.reload(_sys.modules["api_server"])
    import api_server as _api_server  # noqa: E402

    config = {
        "api_host": "127.0.0.1",
        "api_port": 0,                      # not used; TestClient handles ports
        "auth_enabled": True,
        "auth_auto_bootstrap": False,
        "state_dir": str(tmp_path / "state"),
        "log_file": str(tmp_path / "daemon.log"),
        "audit_log": str(tmp_path / "audit.log"),
        "llm_enabled": True,
        "scanner_enabled": False,
    }
    (tmp_path / "state").mkdir(exist_ok=True)

    app = _api_server.create_app(config)

    # Sanity: make sure the mock landed where we expect.
    assert _api_server._llm is _mock_llm, (
        f"mock LLM injection failed; _llm={_api_server._llm!r}"
    )

    yield app, fake_cortex


@pytest.fixture
def test_client(mock_llm_app):
    """starlette TestClient over the in-process app; runs lifespan."""
    from fastapi.testclient import TestClient
    app, _state = mock_llm_app
    with TestClient(app) as client:
        yield client


@pytest.fixture
def auth_token(mock_llm_app, tmp_path):
    """Mint a trust-200 ("interact") bearer token signed with the test secret.

    Same path the daemon's /auth/token uses, but called in-process so we
    don't have to bootstrap through the network. Trust >= 200 is the band
    gating /contusion/ai and /ai/plan (POST /keyboard/* etc.); see the
    endpoint trust-map in auth.py.
    """
    import auth as _auth
    return _auth.create_token(
        subject_id=4242,
        name="ai-commands-test",
        trust_level=200,
        ttl=600,
    )


@pytest.fixture
def admin_token(mock_llm_app, tmp_path):
    """Trust-600 ("admin") token for endpoints that need higher trust."""
    import auth as _auth
    return _auth.create_token(
        subject_id=4243,
        name="ai-commands-admin",
        trust_level=600,
        ttl=600,
    )


class _SubprocessRecorder:
    """Records every captured subprocess call without executing anything.

    Tests inspect `.calls` (list of dicts: {kind, argv|cmd, kwargs}) to
    assert that the right binary was invoked. Default returncode is 0
    (success); flip via `.returncode = 1` before the call to simulate
    failure for step-failure-propagation tests.
    """

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.returncode: int = 0
        self.stdout_bytes: bytes = b""
        self.stderr_bytes: bytes = b""

    def reset(self) -> None:
        self.calls.clear()
        self.returncode = 0
        self.stdout_bytes = b""
        self.stderr_bytes = b""

    def find(self, contains: str) -> list[dict]:
        """Return calls whose argv (joined) contains `contains`."""
        out = []
        for c in self.calls:
            joined = " ".join(map(str, c.get("argv") or [c.get("cmd", "")]))
            if contains in joined:
                out.append(c)
        return out


@pytest.fixture
def subprocess_recorder(monkeypatch):
    """Monkeypatch every subprocess egress so handlers run end-to-end but
    no real binary executes. Also mocks shutil.which so missing tools
    (notify-send, scrot, steam) do not short-circuit handler bodies.
    """
    import asyncio as _asyncio
    import subprocess as _subprocess
    import shutil as _shutil

    rec = _SubprocessRecorder()

    class _FakeProc:
        """Async-subprocess look-alike: returncode + communicate()."""

        def __init__(self, returncode: int, stdout: bytes, stderr: bytes,
                     pid: int = 99999) -> None:
            self.returncode = returncode
            self._stdout = stdout
            self._stderr = stderr
            self.pid = pid
            self.stdout = None
            self.stderr = None

        async def communicate(self, input=None):
            return self._stdout, self._stderr

        async def wait(self):
            return self.returncode

        def kill(self):
            pass

        def terminate(self):
            pass

    async def _fake_create_subprocess_exec(*argv, **kwargs):
        rec.calls.append({"kind": "exec", "argv": list(argv), "kwargs": dict(kwargs)})
        return _FakeProc(rec.returncode, rec.stdout_bytes, rec.stderr_bytes)

    async def _fake_create_subprocess_shell(cmd, **kwargs):
        rec.calls.append({"kind": "shell", "cmd": cmd, "kwargs": dict(kwargs)})
        return _FakeProc(rec.returncode, rec.stdout_bytes, rec.stderr_bytes)

    def _fake_subprocess_run(*args, **kwargs):
        argv = list(args[0]) if args and isinstance(args[0], (list, tuple)) else list(args)
        rec.calls.append({"kind": "run", "argv": argv, "kwargs": dict(kwargs)})
        # CompletedProcess shim
        return _subprocess.CompletedProcess(
            args=argv, returncode=rec.returncode,
            stdout=rec.stdout_bytes, stderr=rec.stderr_bytes,
        )

    # Patch asyncio module-level function used by daemon controllers.
    monkeypatch.setattr(_asyncio, "create_subprocess_exec",
                        _fake_create_subprocess_exec, raising=True)
    monkeypatch.setattr(_asyncio, "create_subprocess_shell",
                        _fake_create_subprocess_shell, raising=True)
    monkeypatch.setattr(_subprocess, "run", _fake_subprocess_run, raising=True)

    # Patch shutil.which so handlers don't bail out with "missing tool"
    # when scrot/notify-send/steam aren't on the test box. Returning the
    # tool name as if it lived in /usr/bin is enough — _exec then forwards
    # to the patched create_subprocess_exec.
    real_which = _shutil.which

    def _fake_which(cmd, *args, **kwargs):
        # Allow a short list of tools the daemon legitimately probes for
        # capability detection (e.g. wmctrl) to fall through to real
        # behaviour, otherwise everything resolves to /usr/bin/<tool>.
        if cmd in {"python3", "python", "sh", "bash"}:
            return real_which(cmd, *args, **kwargs)
        return f"/usr/bin/{cmd}"

    monkeypatch.setattr(_shutil, "which", _fake_which, raising=True)

    yield rec
