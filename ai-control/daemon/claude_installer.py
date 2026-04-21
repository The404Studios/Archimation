"""
claude_installer.py — Self-bootstrap for Claude Code (Session 56, Agent 1).

The daemon can offer to install the official `@anthropic-ai/claude-code`
npm package and seed a default `~/.claude/` workspace when (a) the
operator asks for it via the Contusion handler `app.install_claude` and
(b) the network is reachable.

Three responsibilities:

  1. Reachability check (`check_internet`) -- a stdlib HTTPS probe to
     `https://registry.npmjs.org/-/ping`.  Used as a precondition so we
     never burn time on `npm install -g` while offline.

  2. Install (`install_claude_code`) -- shells out to `npm install -g
     @anthropic-ai/claude-code` with a 5-minute timeout, then verifies
     with `claude --version`.  Returns a structured envelope; never
     raises.

  3. Workspace bootstrap (`bootstrap_workspace`) -- idempotently creates
     `~/.claude/`, a default `CLAUDE.md`, the projects/ tree, and a
     baseline `~/.config/claude/settings.json`.  Existing files are
     preserved unless `force=True`.

Pure stdlib.  Async surface mirrors the rest of the daemon.
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple


async def _arun(fn, *args, **kwargs):
    """Run a sync helper off the event loop.

    Callers on the FastAPI event loop route blocking subprocess helpers
    through ``run_in_executor`` so a hung external binary (5s timeout)
    does not block the single uvicorn event loop thread.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, functools.partial(fn, *args, **kwargs))

logger = logging.getLogger("ai-control.claude_installer")


_NPM_PING_URL = "https://registry.npmjs.org/-/ping"
_INSTALL_TIMEOUT_SECS = 300       # npm install -g can take a while
_VERIFY_TIMEOUT_SECS = 15
_PING_TIMEOUT_SECS = 5.0
_NPM_PACKAGE = "@anthropic-ai/claude-code"


# ---------------------------------------------------------------------------
# Reachability + npm presence
# ---------------------------------------------------------------------------


def check_internet(timeout: float = _PING_TIMEOUT_SECS) -> Tuple[bool, str]:
    """Best-effort HTTPS probe to the npm registry.

    Returns (online, reason).  `reason` is short and operator-friendly.
    """
    req = urllib.request.Request(_NPM_PING_URL, method="GET",
                                 headers={"User-Agent": "ai-control/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if 200 <= resp.status < 400:
                return True, f"reachable ({resp.status})"
            return False, f"unexpected status {resp.status}"
    except urllib.error.HTTPError as e:
        # Non-2xx is still proof-of-life -- the host answered.
        if 200 <= e.code < 500:
            return True, f"reachable ({e.code})"
        return False, f"http {e.code}"
    except urllib.error.URLError as e:
        return False, f"unreachable: {e.reason}"
    except (TimeoutError, OSError) as e:
        return False, f"unreachable: {e}"
    except Exception as e:  # pragma: no cover - defensive
        return False, f"probe failed: {e}"


def check_npm_available() -> Tuple[bool, str]:
    """Verify `npm` is on PATH and prints a version string."""
    npm = shutil.which("npm")
    if not npm:
        return False, "npm not on PATH (try: pacman -S npm nodejs)"
    try:
        out = subprocess.run(
            [npm, "--version"], capture_output=True, text=True,
            timeout=_VERIFY_TIMEOUT_SECS, check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"npm exec failed: {e}"
    ver = (out.stdout or "").strip() or (out.stderr or "").strip()
    if out.returncode != 0:
        return False, f"npm --version rc={out.returncode}: {ver[:200]}"
    return True, ver


async def check_npm_available_async() -> Tuple[bool, str]:
    """Async variant of ``check_npm_available`` — safe to call on the event
    loop.  Uses ``asyncio.create_subprocess_exec`` so a hung ``npm --version``
    invocation (e.g. stuck net probe) never blocks uvicorn's event loop.
    """
    npm = shutil.which("npm")
    if not npm:
        return False, "npm not on PATH (try: pacman -S npm nodejs)"
    try:
        proc = await asyncio.create_subprocess_exec(
            npm, "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (OSError, FileNotFoundError) as e:
        return False, f"npm exec failed: {e}"
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(), timeout=_VERIFY_TIMEOUT_SECS)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return False, f"npm --version timed out after {_VERIFY_TIMEOUT_SECS}s"
    stdout = (out or b"").decode("utf-8", errors="replace")
    stderr = (err or b"").decode("utf-8", errors="replace")
    ver = stdout.strip() or stderr.strip()
    if proc.returncode != 0:
        return False, f"npm --version rc={proc.returncode}: {ver[:200]}"
    return True, ver


def _claude_binary() -> Optional[str]:
    """Find the installed `claude` binary, if any."""
    return shutil.which("claude")


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------


async def install_claude_code(*, force: bool = False) -> Dict:
    """Install (or reinstall) the official Claude Code CLI globally.

    Returns a dict with shape:
        {ok, version, install_dir, log_tail, error?}
    """
    if not force:
        existing = _claude_binary()
        if existing:
            ver_ok, ver = await _read_claude_version_async()
            if ver_ok:
                return {
                    "ok": True,
                    "version": ver,
                    "install_dir": str(Path(existing).parent),
                    "log_tail": f"already installed at {existing}",
                    "skipped": True,
                }
    # check_internet() is stdlib urllib which is sync; push it off the loop.
    online, why = await _arun(check_internet)
    if not online:
        return {
            "ok": False, "version": None, "install_dir": None,
            "log_tail": "", "error": f"offline: {why}",
        }
    npm_ok, npm_msg = await check_npm_available_async()
    if not npm_ok:
        return {
            "ok": False, "version": None, "install_dir": None,
            "log_tail": "", "error": npm_msg,
        }
    npm = shutil.which("npm") or "npm"
    argv = [npm, "install", "-g", _NPM_PACKAGE]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "CI": "1"},  # silence interactive prompts
        )
    except (FileNotFoundError, PermissionError, OSError) as e:
        return {
            "ok": False, "version": None, "install_dir": None,
            "log_tail": "", "error": f"npm exec failed: {e}",
        }
    try:
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=_INSTALL_TIMEOUT_SECS)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return {
            "ok": False, "version": None, "install_dir": None,
            "log_tail": "",
            "error": f"timeout after {_INSTALL_TIMEOUT_SECS}s",
        }
    log = (stdout or b"").decode("utf-8", errors="replace")
    log_tail = "\n".join(log.splitlines()[-20:])
    if proc.returncode != 0:
        return {
            "ok": False, "version": None, "install_dir": None,
            "log_tail": log_tail,
            "error": f"npm install rc={proc.returncode}",
        }
    # Verify install
    bin_path = _claude_binary()
    if not bin_path:
        return {
            "ok": False, "version": None, "install_dir": None,
            "log_tail": log_tail,
            "error": "npm reported success but `claude` not on PATH",
        }
    ver_ok, ver = await _read_claude_version_async()
    return {
        "ok": ver_ok,
        "version": ver if ver_ok else None,
        "install_dir": str(Path(bin_path).parent),
        "log_tail": log_tail,
        "error": None if ver_ok else "claude --version failed",
    }


def _read_claude_version() -> Tuple[bool, str]:
    bin_path = _claude_binary()
    if not bin_path:
        return False, "not installed"
    try:
        out = subprocess.run(
            [bin_path, "--version"], capture_output=True, text=True,
            timeout=_VERIFY_TIMEOUT_SECS, check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"exec failed: {e}"
    if out.returncode != 0:
        return False, f"rc={out.returncode}"
    return True, (out.stdout or out.stderr or "").strip()


async def _read_claude_version_async() -> Tuple[bool, str]:
    """Async variant of ``_read_claude_version``.  Safe to call on the event
    loop — never blocks on a hung ``claude --version`` invocation.
    """
    bin_path = _claude_binary()
    if not bin_path:
        return False, "not installed"
    try:
        proc = await asyncio.create_subprocess_exec(
            bin_path, "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (OSError, FileNotFoundError) as e:
        return False, f"exec failed: {e}"
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(), timeout=_VERIFY_TIMEOUT_SECS)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return False, f"timeout after {_VERIFY_TIMEOUT_SECS}s"
    if proc.returncode != 0:
        return False, f"rc={proc.returncode}"
    stdout = (out or b"").decode("utf-8", errors="replace")
    stderr = (err or b"").decode("utf-8", errors="replace")
    return True, (stdout or stderr).strip()


# ---------------------------------------------------------------------------
# Workspace bootstrap
# ---------------------------------------------------------------------------


_DEFAULT_CLAUDE_MD = """\
# Default Claude Code Workspace (AI Arch Linux)

You are operating inside a default Claude Code workspace on AI Arch Linux,
a custom distribution with a Python/FastAPI AI control daemon (port 8420),
a biologically-inspired trust kernel module, and native Windows PE
execution via a custom loader.

## Recommended model

claude-opus-4-7 (1M context) for normal sessions; sonnet for cost-sensitive
loops.

## Conventions

- Edit existing files in place; do not scatter new ones unless asked.
- Never commit unless the user explicitly says to commit.
- Respect the emergency-latch contract: any mutating call may 409 if the
  cortex has tripped the latch -- back off, don't retry-storm.
- Use absolute paths in all bash commands; the WSL2/NTFS bridge is finicky.
- For systemd unit edits, add a drop-in under /etc/systemd/system/<unit>.d/
  rather than editing the shipped unit.

## Safety defaults

- No `rm -rf /`.  No `chmod -R 777`.  No `dd` to a block device without
  triple-confirmation.
- Treat `/dev/trust` and the trust kernel module as a kernel surface --
  never poke unknown ioctls at it.

## Useful endpoints (AI control daemon, default port 8420)

- POST /contusion/run       -- typed handler dispatch
- POST /contusion/pipeline  -- multi-step plan
- GET  /emergency/status    -- read latch
- POST /emergency/clear     -- clear latch (operator-only)
- GET  /system/summary      -- one-shot health

Generated by ai-control claude_installer.bootstrap_workspace.
"""

_DEFAULT_SETTINGS_JSON = {
    "model": "claude-opus-4-7",
    "telemetry": False,
    "autoUpdate": True,
    "editor": {
        "tabWidth": 4,
        "insertFinalNewline": True,
    },
    "permissions": {
        "allow": [
            "Bash(ls:*)",
            "Bash(cat:*)",
            "Bash(grep:*)",
            "Bash(rg:*)",
            "Bash(git status)",
            "Bash(git diff:*)",
            "Bash(git log:*)",
        ],
        "deny": [
            "Bash(rm -rf /:*)",
            "Bash(dd if=*/dev/sd*)",
        ],
    },
}


def bootstrap_workspace(home: Optional[Path] = None,
                        force: bool = False) -> Dict:
    """Create the default `~/.claude/` workspace.

    Idempotent: existing files are NOT overwritten unless force=True.
    Returns {created, skipped, errors}.
    """
    if home is None:
        home = Path(os.environ.get("HOME") or os.path.expanduser("~"))
    created: List[str] = []
    skipped: List[str] = []
    errors: List[str] = []

    def _mkdir(p: Path) -> None:
        try:
            p.mkdir(parents=True, exist_ok=True)
            if str(p) not in created:
                created.append(str(p))
        except OSError as e:
            errors.append(f"{p}: {e}")

    def _write(p: Path, content: str) -> None:
        try:
            if p.exists() and not force:
                skipped.append(str(p))
                return
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            created.append(str(p))
        except OSError as e:
            errors.append(f"{p}: {e}")

    claude_dir = home / ".claude"
    projects_default = claude_dir / "projects" / "default"
    config_dir = home / ".config" / "claude"

    _mkdir(claude_dir)
    _mkdir(projects_default)
    _mkdir(config_dir)

    _write(claude_dir / "CLAUDE.md", _DEFAULT_CLAUDE_MD)
    _write(config_dir / "settings.json",
           json.dumps(_DEFAULT_SETTINGS_JSON, indent=2) + "\n")

    return {
        "ok": not errors,
        "created": created,
        "skipped": skipped,
        "errors": errors,
        "home": str(home),
    }


# ---------------------------------------------------------------------------
# Composite
# ---------------------------------------------------------------------------


async def install_and_bootstrap(force_install: bool = False,
                                force_bootstrap: bool = False) -> Dict:
    """Install Claude Code, then seed the workspace.

    If install fails (offline / npm missing / etc.) the bootstrap step is
    SKIPPED -- there is no value in seeding `~/.claude/` for a CLI that
    doesn't exist.  Caller can still run `bootstrap_workspace` directly.
    """
    install = await install_claude_code(force=force_install)
    if not install.get("ok"):
        return {
            "ok": False,
            "install": install,
            "bootstrap": None,
            "error": install.get("error", "install failed"),
        }
    boot = bootstrap_workspace(force=force_bootstrap)
    return {
        "ok": bool(install.get("ok") and boot.get("ok")),
        "install": install,
        "bootstrap": boot,
        "error": None,
    }


# ---------------------------------------------------------------------------
# Self-test (python3 claude_installer.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    print(json.dumps({
        "internet": check_internet(),
        "npm": check_npm_available(),
        "claude_binary": _claude_binary(),
    }, indent=2))
