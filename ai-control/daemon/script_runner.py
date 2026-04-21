"""
script_runner.py — Operator script-extension surface (Session 56, Agent 1).

Lets an operator extend the daemon's executable verbs by dropping a `.sh`
file into one of two well-known locations:

    /etc/ai-control/scripts.d/    (system-wide, root-owned)
    ~/.ai/scripts.d/              (per-user)

Discovery walks both directories, parses the header metadata block (a
small set of `# AI-Foo: bar` comments at the top of the file) and returns
a list of script descriptors. Execution goes through
`asyncio.create_subprocess_exec` -- never `shell=True` -- and the args
list always passes through `safety.Sanitizer.argv` first.

Header format (any field optional; defaults applied):

    #!/bin/bash
    # AI-Description: One-line description shown to operator + LLM
    # AI-Confirm: yes|no                       (default: yes)
    # AI-Network: required|optional|prohibited (default: optional)
    # AI-Trust-Band: 100|200|400|600           (default: 200)
    # AI-Args: <free-form, informational only>

Security model (defence in depth, not authority root):
  * SYSTEM scripts must be owned by root and not world-writable.
  * USER scripts must be owned by the invoking uid and not world-writable.
  * Script names are restricted to `[A-Za-z0-9._-]{1,128}` -- no '/',
    no '..', no NUL.  Discovery silently drops anything that fails.
  * Header `AI-Trust-Band` is *informational* -- the actual gate is the
    auth middleware on `/contusion/run`, plus the standard emergency
    latch.  We surface it so operator tooling can warn ("this script is
    marked 600, your session is 200").

Pure stdlib.  Imports `safety` from this package.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import time
from pathlib import Path
from typing import Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

try:
    from .safety import Sanitizer, SanitizerError
except ImportError:  # pragma: no cover - script-style import
    from safety import Sanitizer, SanitizerError  # type: ignore[no-redef]

logger = logging.getLogger("ai-control.script_runner")

SYSTEM_SCRIPTS_DIR = Path("/etc/ai-control/scripts.d")


def _user_scripts_dir() -> Path:
    """Per-user scripts directory.  Honours $HOME so unit-tests can override."""
    home = Path(os.environ.get("HOME") or os.path.expanduser("~"))
    return home / ".ai" / "scripts.d"


# Names that are accepted as a script.  Note: no '/', no '..', no NUL.
# We additionally reject leading '.' so dotfiles (like editor backups) are
# silently dropped.
_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")

# Recognised header keys -> metadata field names.
_HEADER_KEYS = {
    "ai-description": "description",
    "ai-confirm": "requires_confirm_raw",
    "ai-network": "requires_network",
    "ai-trust-band": "trust_band_raw",
    "ai-args": "args_spec",
}

_HEADER_LINE_RE = re.compile(
    r"^\s*#\s*(AI-[A-Za-z-]+)\s*:\s*(.*?)\s*$"
)

_VALID_NETWORK = frozenset({"required", "optional", "prohibited"})
_VALID_TRUST_BANDS = (100, 200, 400, 600)
_DEFAULT_TIMEOUT = 30
_MAX_TIMEOUT = 600  # 10 minutes ceiling -- script_runner is not a daemon host
_MAX_HEADER_BYTES = 4096  # only scan the top of the file for headers


def _parse_header(path: Path) -> Dict[str, str]:
    """Read up to _MAX_HEADER_BYTES from *path* and parse `# AI-Foo:` lines.

    Returns an empty dict on any IO error (caller treats as 'no header').
    """
    try:
        with open(path, "rb") as f:
            blob = f.read(_MAX_HEADER_BYTES)
    except OSError as e:
        logger.debug("script header read failed for %s: %s", path, e)
        return {}
    text = blob.decode("utf-8", errors="replace")
    out: Dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        # Stop at first non-comment, non-shebang line -- header ends.
        s = line.lstrip()
        if not s.startswith("#"):
            break
        m = _HEADER_LINE_RE.match(line)
        if not m:
            continue
        key = m.group(1).lower()
        if key in _HEADER_KEYS:
            out[_HEADER_KEYS[key]] = m.group(2)
    return out


def _coerce_bool(s: Optional[str], default: bool) -> bool:
    if s is None:
        return default
    return s.strip().lower() in ("yes", "true", "1", "on")


def _coerce_trust_band(s: Optional[str]) -> int:
    if s is None:
        return 200
    try:
        v = int(s.strip())
    except (TypeError, ValueError):
        return 200
    if v not in _VALID_TRUST_BANDS:
        return 200
    return v


def _coerce_network(s: Optional[str]) -> str:
    if s is None:
        return "optional"
    val = s.strip().lower()
    if val not in _VALID_NETWORK:
        return "optional"
    return val


def _is_safe_owner(path: Path, source: str) -> Tuple[bool, str]:
    """Verify ownership and permissions for *path*.

    SYSTEM scripts: must be uid 0, must not be world-writable.
    USER scripts: must be owned by current uid, must not be world-writable.
    """
    try:
        st = path.stat()
    except OSError as e:
        return False, f"stat() failed: {e}"
    if st.st_mode & 0o002:
        return False, "world-writable"
    if source == "system":
        if st.st_uid != 0:
            return False, f"system script not owned by root (uid={st.st_uid})"
    else:  # user
        try:
            cur_uid = os.getuid()
        except AttributeError:  # Windows -- shouldn't happen in prod, but skip
            return True, ""
        if st.st_uid != cur_uid:
            return False, f"user script not owned by uid={cur_uid}"
    return True, ""


def _scan_dir(root: Path, source: str) -> List[Dict]:
    """Walk *root* one level deep and yield validated script descriptors."""
    out: List[Dict] = []
    if not root.is_dir():
        return out
    try:
        entries = sorted(root.iterdir())
    except OSError as e:
        logger.warning("script dir scan failed %s: %s", root, e)
        return out
    for entry in entries:
        try:
            if not entry.is_file():
                continue
        except OSError:
            continue
        # S56 fix: scripts on disk are <name>.sh but callers (LLM, ai CLI,
        # NL dictionary) invoke as `script.run hello` not `hello.sh`.
        # Strip the .sh suffix so the user-visible "name" matches the
        # filename stem.  Other suffixes are allowed-but-not-stripped.
        raw_name = entry.name
        name = raw_name[:-3] if raw_name.endswith(".sh") else raw_name
        if not _NAME_RE.match(name):
            logger.debug("script name rejected: %r (from %r)", name, raw_name)
            continue
        ok, why = _is_safe_owner(entry, source)
        if not ok:
            logger.warning("script %s rejected: %s", entry, why)
            continue
        # Executability is checked at run-time.  We list non-+x scripts so
        # operators see them and learn to chmod.
        hdr = _parse_header(entry)
        out.append({
            "name": name,
            "path": str(entry),
            "description": hdr.get("description", "(no description)"),
            "requires_confirm": _coerce_bool(
                hdr.get("requires_confirm_raw"), default=True),
            "requires_network": _coerce_network(hdr.get("requires_network")),
            "trust_band": _coerce_trust_band(hdr.get("trust_band_raw")),
            "args_spec": hdr.get("args_spec", ""),
            "source": source,
            "executable": os.access(str(entry), os.X_OK),
        })
    return out


def list_scripts(include_user: bool = True) -> List[Dict]:
    """Discover scripts in both system and (optionally) user directories.

    System entries are listed first; user entries are appended.  Names
    that collide are NOT deduped -- caller can see both and decide.
    """
    out: List[Dict] = _scan_dir(SYSTEM_SCRIPTS_DIR, "system")
    if include_user:
        out.extend(_scan_dir(_user_scripts_dir(), "user"))
    return out


def get_script(name: str, include_user: bool = True) -> Optional[Dict]:
    """Look up a single script by name.  Returns None if not found.

    System scripts win on a name collision (defence: a user can't shadow
    a system handler with the same name).
    """
    if not isinstance(name, str) or not _NAME_RE.match(name):
        return None
    for entry in list_scripts(include_user=include_user):
        if entry["name"] == name:
            return entry
    return None


async def run_script(
    name: str,
    args: Optional[List[str]] = None,
    timeout: int = _DEFAULT_TIMEOUT,
    env: Optional[Dict[str, str]] = None,
) -> Dict:
    """Execute a discovered script and return a standard envelope.

    Args go through `Sanitizer.argv` -- callers cannot smuggle shell
    metacharacters even though the script itself is bash.
    """
    handler = "script.run"
    # Validate name strictly (also blocks '..' / '/' / NUL).
    if not isinstance(name, str) or not _NAME_RE.match(name):
        return {
            "handler": handler, "ok": False, "returncode": 2,
            "stdout": "", "stderr": f"invalid script name: {name!r}",
            "elapsed_s": 0.0, "name": name,
        }
    info = get_script(name)
    if info is None:
        return {
            "handler": handler, "ok": False, "returncode": 127,
            "stdout": "", "stderr": f"script not found: {name}",
            "elapsed_s": 0.0, "name": name,
        }
    if not info["executable"]:
        return {
            "handler": handler, "ok": False, "returncode": 126,
            "stdout": "",
            "stderr": f"script not executable (chmod +x {info['path']})",
            "elapsed_s": 0.0, "name": name,
        }
    # Validate args via Sanitizer.argv -- coerces to List[str] and strips
    # any shell metacharacters / NUL bytes.
    if args is None:
        args = []
    try:
        clean_args = Sanitizer.argv(args, max_args=32)
    except SanitizerError as e:
        return {
            "handler": handler, "ok": False, "returncode": 2,
            "stdout": "", "stderr": e.as_dict()["message"],
            "elapsed_s": 0.0, "name": name,
        }
    # Clamp timeout to a sensible range.
    try:
        t = int(timeout)
    except (TypeError, ValueError):
        t = _DEFAULT_TIMEOUT
    t = max(1, min(_MAX_TIMEOUT, t))
    # Build env -- do NOT inherit secrets blindly.  Start from a minimal
    # set then overlay caller-supplied env.
    base_env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "DISPLAY": os.environ.get("DISPLAY", ":0"),
        "AI_SCRIPT_NAME": name,
        "AI_SCRIPT_SOURCE": info["source"],
    }
    if env:
        # Reject any env entry whose key/value contains NUL.
        for k, v in env.items():
            if not isinstance(k, str) or not isinstance(v, str):
                continue
            if "\x00" in k or "\x00" in v:
                continue
            base_env[k] = v
    # Spawn -- always exec, never shell.
    argv = [info["path"], *clean_args]
    t0 = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=base_env,
            start_new_session=True,
        )
    except FileNotFoundError:
        return {
            "handler": handler, "ok": False, "returncode": 127,
            "stdout": "", "stderr": "ENOENT: cannot exec script",
            "elapsed_s": 0.0, "name": name,
        }
    except PermissionError as e:
        return {
            "handler": handler, "ok": False, "returncode": 126,
            "stdout": "", "stderr": f"EPERM: {e}",
            "elapsed_s": 0.0, "name": name,
        }
    except OSError as e:
        return {
            "handler": handler, "ok": False, "returncode": -1,
            "stdout": "", "stderr": f"OSError: {e}",
            "elapsed_s": 0.0, "name": name,
        }
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=t)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return {
            "handler": handler, "ok": False, "returncode": -1,
            "stdout": "",
            "stderr": f"timeout after {t}s",
            "elapsed_s": time.monotonic() - t0, "name": name,
        }
    elapsed = time.monotonic() - t0
    rc = proc.returncode if proc.returncode is not None else -1
    return {
        "handler": handler,
        "ok": rc == 0,
        "returncode": rc,
        "stdout": stdout.decode("utf-8", errors="replace").strip(),
        "stderr": stderr.decode("utf-8", errors="replace").strip(),
        "elapsed_s": elapsed,
        "name": name,
        "source": info["source"],
        "trust_band": info["trust_band"],
    }


# ---------------------------------------------------------------------------
# Self-test (python3 script_runner.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    import json
    print(json.dumps({"system_dir": str(SYSTEM_SCRIPTS_DIR),
                      "user_dir": str(_user_scripts_dir()),
                      "scripts": list_scripts()},
                     indent=2))
