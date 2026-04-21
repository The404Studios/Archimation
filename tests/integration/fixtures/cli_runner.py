"""CLI-runner harness for end-to-end ``ai`` CLI tests.

Session 53, Agent 5. Companion to ``mock_llm.py``.

The ``ai`` CLI at ``ai-control/cli/ai`` is a stdlib-only Python script that
POSTs to a daemon at the URL it reads from ``~/.ai/config.toml``.  We can't
run the CLI as a subprocess against the in-process FastAPI ``TestClient``
because TestClient does not expose a real socket.  Instead this module
ships:

  * :func:`run_ai_cli` – spawn the CLI in a subprocess with a temp ``HOME``
    that contains a ``.ai/config.toml`` pointing at a chosen daemon URL.
    Captures stdout/stderr, supports stdin piping for the interactive
    confirm prompt, returns ``(returncode, stdout, stderr)``.
  * :class:`StubDaemon` – a tiny stdlib HTTP server that returns
    CLI-shaped JSON for ``/contusion/ai``, ``/contusion/confirm``,
    ``/contusion/execute``, ``/ai/plan``, ``/ai/plan/execute`` and
    ``/emergency/status``.  Records every request so the test can
    introspect ``what was POSTed`` after the CLI exits.  The handler
    behaviour is switchable via the public mutators: ``set_low_conf()``,
    ``set_emergency_active()``, ``set_execute_failure()``, etc.

The stub is intentionally NOT the real daemon: we want a hermetic check
that the **CLI** behaves correctly given a known-good wire shape.  Tests
that exercise the daemon's ``/contusion/ai`` end-to-end live in
``test_ai_commands.py`` (S52, Agent Z).

No production code is touched.  Hermetic: stdlib http.server +
subprocess + tempfile only.
"""
from __future__ import annotations

import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from http import HTTPStatus
from pathlib import Path
from typing import Any, Callable, Iterator, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parents[3]
AI_CLI_PATH = REPO_ROOT / "ai-control" / "cli" / "ai"


# ---------------------------------------------------------------------------
# CLI subprocess runner
# ---------------------------------------------------------------------------


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _write_config(home: Path, daemon_url: str, token: str = "",
                  threshold: float = 0.85) -> None:
    """Write a CLI config TOML into ``home/.ai/config.toml``.

    The CLI's :func:`load_config` reads ``daemon_url``, ``auth_token``,
    ``auto_confirm_threshold``, ``verbosity``, and ``editor`` from this
    path.  We only set the three the tests care about.
    """
    ai_dir = home / ".ai"
    ai_dir.mkdir(parents=True, exist_ok=True)
    cfg = ai_dir / "config.toml"
    cfg.write_text(
        f'daemon_url = "{daemon_url}"\n'
        f'auth_token = "{token}"\n'
        f'auto_confirm_threshold = {threshold}\n'
        'verbosity = "normal"\n'
        'editor = ""\n'
    )


def run_ai_cli(
    *args: str,
    daemon_url: Optional[str] = None,
    token: Optional[str] = None,
    stdin_input: Optional[str] = None,
    timeout: float = 15.0,
    env_extra: Optional[dict] = None,
    home: Optional[Path] = None,
) -> Tuple[int, str, str]:
    """Run the ``ai`` CLI in a subprocess, return ``(rc, stdout, stderr)``.

    Parameters
    ----------
    *args
        Positional argv passed straight through to the CLI (e.g.
        ``"take", "a", "screenshot"`` or ``"--dry-run", "do", "thing"``).
    daemon_url
        URL the CLI should POST to.  Wired in via ``~/.ai/config.toml`` in
        a freshly minted tempdir HOME (the CLI does not accept
        ``--daemon-url`` as a flag).  If ``None``, the CLI defaults
        (``http://127.0.0.1:8420``) apply.
    token
        Bearer token written into the config and additionally passed via
        ``--token`` so we test both code paths.
    stdin_input
        String fed into the CLI's stdin, e.g. ``"y\\n"`` to confirm the
        plan.  When ``None`` the CLI sees a closed stdin (which it
        treats as "n").
    timeout
        Wall-clock seconds before the subprocess is killed.
    env_extra
        Extra environment variables to merge into the subprocess env
        (after our HOME / NO_COLOR setup).
    home
        Pre-existing tempdir to use as ``HOME``.  When ``None`` we mint
        one and clean it up after the call.
    """
    if not AI_CLI_PATH.exists():
        raise FileNotFoundError(f"ai CLI not found at {AI_CLI_PATH}")

    cleanup_home = False
    if home is None:
        home = Path(tempfile.mkdtemp(prefix="ai-cli-test-"))
        cleanup_home = True
    try:
        if daemon_url is not None:
            _write_config(home, daemon_url, token=token or "")

        env = os.environ.copy()
        env["HOME"] = str(home)
        # Windows fallback for any code that consults USERPROFILE.
        env["USERPROFILE"] = str(home)
        # Strip ANSI to make stdout assertions stable regardless of
        # whether the CLI thinks it has a TTY.
        env["NO_COLOR"] = "1"
        # Unset proxies in case the CI environment injects them.
        for k in ("HTTP_PROXY", "HTTPS_PROXY",
                  "http_proxy", "https_proxy"):
            env.pop(k, None)
        if env_extra:
            env.update(env_extra)

        cli_argv: List[str] = [sys.executable, str(AI_CLI_PATH)]
        if token:
            cli_argv.extend(["--token", token])
        cli_argv.extend(args)

        proc = subprocess.run(
            cli_argv,
            input=stdin_input,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    finally:
        if cleanup_home:
            import shutil
            shutil.rmtree(home, ignore_errors=True)


# ---------------------------------------------------------------------------
# Stub daemon — CLI-shaped responses + request recording
# ---------------------------------------------------------------------------


class StubDaemon:
    """Tiny HTTP server emulating the daemon endpoints the ``ai`` CLI
    talks to.  Returns JSON in the shape the CLI's ``_extract_plan``
    understands (top-level ``plan: {...}``).

    The server records every request in :attr:`requests` so tests can
    assert on what the CLI POSTed.  Behaviour mutators are public:

    * :attr:`low_conf`        – return a 0.10-confidence plan so the CLI
      hits the "Low confidence" branch (exit 2).
    * :attr:`emergency_active` – return 409 from any mutating endpoint
      with body ``{"error": "blocked by emergency latch"}``.  The CLI
      surfaces that at exit 3.
    * :attr:`execute_failure`  – return success=False from
      ``/contusion/execute`` so the CLI prints ``[FAIL]`` and exits 3.
    * :attr:`auth_required`    – return 401 from ``/contusion/ai``
      regardless of token so we can drive the CLI's exit-4 path.
    * :attr:`offline`          – do not bind a port; any CLI request
      ECONNREFUSEDs.  Used to test the daemon-unreachable exit-4 path.

    Multi-step planner endpoints (``/ai/plan`` and ``/ai/plan/execute``)
    are also stubbed even though the CLI doesn't yet call them — tests
    can drive the planner directly via :func:`urllib.request.urlopen`
    against ``self.url`` to mimic the future CLI subcommand.
    """

    def __init__(self) -> None:
        self.requests: List[dict] = []
        self.low_conf: bool = False
        self.emergency_active: bool = False
        self.execute_failure: bool = False
        self.auth_required: bool = False
        self.offline: bool = False
        # Multi-step planner state.
        self._plan_id_seq = 0
        self._plans: dict = {}
        self.executed_steps: List[dict] = []
        # Fake "subprocess" record: records what the planner WOULD spawn.
        self.subprocess_calls: List[List[str]] = []
        # Server bookkeeping (filled in __enter__).
        self._srv: Optional[http.server.ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._port: int = 0

    # ---- lifecycle -------------------------------------------------------

    @property
    def url(self) -> str:
        if self.offline:
            # Return a closed port so anything pointed at this URL fails.
            return f"http://127.0.0.1:{self._port or 65530}"
        return f"http://127.0.0.1:{self._port}"

    def __enter__(self) -> "StubDaemon":
        if self.offline:
            # Pick a port we will NOT bind, simulating a dead daemon.
            self._port = _pick_free_port()
            return self
        outer = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # silence stderr spam
                return

            def _read_body(self) -> dict:
                length = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    return json.loads(raw.decode("utf-8")) if raw else {}
                except Exception:
                    return {"_raw": raw.decode("utf-8", "replace")}

            def _record(self, method: str, body: dict) -> None:
                outer.requests.append({
                    "method": method,
                    "path": self.path,
                    "body": body,
                    "headers": {k: v for k, v in self.headers.items()},
                })

            def _send(self, code: int, body: dict) -> None:
                payload = json.dumps(body).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            # --- GET handlers ----------------------------------------

            def do_GET(self):  # noqa: N802 (stdlib API)
                self._record("GET", {})
                if self.path.startswith("/health"):
                    return self._send(HTTPStatus.OK, {"status": "ok"})
                if self.path.startswith("/emergency/status"):
                    return self._send(HTTPStatus.OK, {
                        "active": outer.emergency_active,
                        "since": "" if not outer.emergency_active else "now",
                        "triggered_by": "test",
                    })
                self.send_error(HTTPStatus.NOT_FOUND)

            # --- POST handlers ---------------------------------------

            def do_POST(self):  # noqa: N802
                body = self._read_body()
                self._record("POST", body)
                path = self.path.split("?", 1)[0]

                # Auth gate (simulates daemon middleware).  We only enforce
                # it when ``auth_required`` is set so tests that DON'T care
                # about auth still pass.
                if outer.auth_required and not self.headers.get("Authorization"):
                    return self._send(HTTPStatus.UNAUTHORIZED,
                                      {"error": "auth required"})

                # Emergency latch — fires for ALL mutating endpoints.  The
                # CLI's ``/contusion/ai`` POST is what trips this in the
                # tests; the CLI surfaces a non-zero exit and prints the
                # daemon's body verbatim if --verbose.
                if outer.emergency_active and path in (
                    "/contusion/ai", "/contusion/confirm",
                    "/contusion/execute", "/ai/plan", "/ai/plan/execute",
                ):
                    return self._send(HTTPStatus.CONFLICT, {
                        "error": "blocked by emergency latch",
                        "summary": "blocked by emergency latch — "
                                   "clear /emergency to proceed",
                        "latch": "active",
                        "emergency": True,
                    })

                if path == "/contusion/ai":
                    return self._handle_contusion_ai(body)
                if path == "/contusion/confirm":
                    return self._send(HTTPStatus.OK, {
                        "status": "ok", "success": True,
                        "command": body.get("command")
                                   or body.get("value", ""),
                        "summary": "confirmed",
                    })
                if path == "/contusion/execute":
                    return self._handle_contusion_execute(body)
                if path == "/ai/plan":
                    return self._handle_ai_plan(body)
                if path == "/ai/plan/execute":
                    return self._handle_ai_plan_execute(body)
                self.send_error(HTTPStatus.NOT_FOUND)

            # --- per-endpoint handler bodies -------------------------

            def _handle_contusion_ai(self, body: dict):
                instr = (body.get("instruction") or "").lower()
                conf = 0.10 if (outer.low_conf
                                or "inscrutable" in instr) else 0.95
                handler = "screenshot"
                args: dict = {}
                if "install" in instr and "firefox" in instr:
                    handler, args = "app.install_firefox", {}
                elif "install" in instr and "steam" in instr:
                    handler, args = "app.install_steam", {}
                # CLI shape (a): top-level "plan" dict.
                return self._send(HTTPStatus.OK, {
                    "plan": {
                        "handler_type": handler,
                        "args": args,
                        "confidence": conf,
                        "rationale": (
                            "stub: matched instruction"
                            if conf >= 0.6
                            else "stub: low-confidence fallback"
                        ),
                    },
                    "instruction": instr,
                    "clarifying_question": (
                        "could you rephrase? I don't recognise that"
                        if conf < 0.6 else None
                    ),
                })

            def _handle_contusion_execute(self, body: dict):
                ok = not outer.execute_failure
                return self._send(HTTPStatus.OK, {
                    "status": "ok" if ok else "error",
                    "success": ok,
                    "summary": ("executed handler "
                                f"{body.get('action')!r}") if ok
                               else "stub-induced failure",
                    "instruction": body.get("instruction"),
                    "result": {"returncode": 0 if ok else 1},
                })

            def _handle_ai_plan(self, body: dict):
                instr = (body.get("instruction") or "").lower()
                # Build a 3-step plan when the instruction reads as
                # "install steam, launch it, turn on gamescope".
                steps: List[dict] = []
                if "steam" in instr:
                    steps.append({
                        "index": 0,
                        "handler_type": "app.install_steam",
                        "args": {},
                        "depends_on": [],
                    })
                if "launch" in instr:
                    steps.append({
                        "index": len(steps),
                        "handler_type": "app.launch",
                        "args": {"name": "steam"},
                        "depends_on": [0] if steps else [],
                    })
                if "gamescope" in instr:
                    # No dep on previous steps so a step-0 failure does
                    # NOT cascade to gamescope (matches spec).
                    steps.append({
                        "index": len(steps),
                        "handler_type": "perf.gamescope_on",
                        "args": {},
                        "depends_on": [],
                    })
                if not steps:
                    return self._send(HTTPStatus.BAD_REQUEST, {
                        "error": "could not decompose instruction",
                    })
                outer._plan_id_seq += 1
                pid = f"plan-{outer._plan_id_seq:04d}"
                outer._plans[pid] = {"steps": steps, "instruction": instr}
                return self._send(HTTPStatus.OK, {
                    "plan_id": pid,
                    "steps": steps,
                    "instruction": body.get("instruction"),
                    "summary": f"plan with {len(steps)} steps",
                })

            def _handle_ai_plan_execute(self, body: dict):
                pid = body.get("plan_id") or ""
                dry = bool(body.get("dry_run", False))
                plan = outer._plans.get(pid)
                if plan is None:
                    return self._send(HTTPStatus.NOT_FOUND,
                                      {"error": "plan not found"})
                results: List[dict] = []
                step_status: dict = {}
                for step in plan["steps"]:
                    idx = step["index"]
                    deps = step.get("depends_on") or []
                    failed_dep = any(
                        step_status.get(d) == "failed" for d in deps
                    )
                    if failed_dep:
                        results.append({
                            "index": idx,
                            "status": "skipped_dep_failed",
                            "handler_type": step["handler_type"],
                        })
                        step_status[idx] = "skipped_dep_failed"
                        continue
                    if dry:
                        results.append({
                            "index": idx,
                            "status": "dry_run",
                            "handler_type": step["handler_type"],
                        })
                        step_status[idx] = "dry_run"
                        continue
                    # "Execute" — record the would-be subprocess call.
                    argv = _argv_for_handler(step["handler_type"],
                                             step.get("args") or {})
                    outer.subprocess_calls.append(argv)
                    outer.executed_steps.append(step)
                    # First-step failure injection: when the test sets
                    # ``execute_failure`` we fail step 0 only, so step 2
                    # (no dep on 0) still runs.
                    if outer.execute_failure and idx == 0:
                        results.append({
                            "index": idx,
                            "status": "failed",
                            "handler_type": step["handler_type"],
                            "returncode": 1,
                        })
                        step_status[idx] = "failed"
                    else:
                        results.append({
                            "index": idx,
                            "status": "completed",
                            "handler_type": step["handler_type"],
                            "returncode": 0,
                        })
                        step_status[idx] = "completed"
                completed = sum(1 for r in results if r["status"] == "completed")
                failed = sum(1 for r in results if r["status"] == "failed")
                skipped = sum(1 for r in results
                              if r["status"] in
                              ("skipped_dep_failed", "dry_run"))
                return self._send(HTTPStatus.OK, {
                    "plan_id": pid,
                    "results": results,
                    "completed": completed,
                    "failed": failed,
                    "skipped": skipped,
                    "dry_run": dry,
                })

        # Bind, start the serving thread.
        port = _pick_free_port()
        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", port),
                                                    _Handler)
        self._port = port
        self._thread = threading.Thread(target=self._srv.serve_forever,
                                        daemon=True)
        self._thread.start()
        # Tiny readiness check — getsockname guaranteed bound by ctor.
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._srv is not None:
            self._srv.shutdown()
            self._srv.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    # ---- introspection helpers ------------------------------------------

    def find_request(self, path: str, method: str = "POST") -> List[dict]:
        return [r for r in self.requests
                if r["method"] == method and r["path"] == path]

    def reset(self) -> None:
        self.requests.clear()
        self.subprocess_calls.clear()
        self.executed_steps.clear()
        self.low_conf = False
        self.emergency_active = False
        self.execute_failure = False
        self.auth_required = False


def _argv_for_handler(handler_type: str, args: dict) -> List[str]:
    """Map a handler_type to the canonical argv we pretend it ran.

    Mirrors what the live ``contusion_handlers`` would do — used to
    populate :attr:`StubDaemon.subprocess_calls` so tests can assert
    ``the planner WOULD HAVE called pacman -S steam``.
    """
    if handler_type == "app.install_steam":
        return ["pacman", "-S", "--needed", "--noconfirm", "steam"]
    if handler_type == "app.install_firefox":
        return ["pacman", "-S", "--needed", "--noconfirm", "firefox"]
    if handler_type == "app.launch":
        return [args.get("name") or args.get("app") or "steam"]
    if handler_type == "perf.gamescope_on":
        return ["sh", "-c",
                "echo 'export GAME_LAUNCH_PREFIX=\"gamescope ...\"' "
                ">> ~/.config/contusion-perf.sh"]
    if handler_type == "screenshot":
        return ["scrot", "/tmp/screenshot.png"]
    return [handler_type]


@contextmanager
def stub_daemon(**flags: Any) -> Iterator[StubDaemon]:
    """Sugar context manager: ``with stub_daemon(low_conf=True) as d: ...``."""
    d = StubDaemon()
    for k, v in flags.items():
        if not hasattr(d, k):
            raise AttributeError(f"unknown StubDaemon flag: {k!r}")
        setattr(d, k, v)
    with d:
        yield d
