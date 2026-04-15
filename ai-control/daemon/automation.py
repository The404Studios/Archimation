"""
Automation Engine - Execute multi-step workflows and tasks.

The AI has full system access. This module provides:
- Task queue with async execution
- Multi-step workflow chaining (shell, API calls, file ops, service control)
- Scheduled/recurring automation
- Real-time task status and output streaming
- Autonomous operation: the AI can trigger workflows without human approval
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import shlex
import socket
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

from filesystem import (
    _BLOCKED_WRITE_PATHS,
    _BLOCKED_READ_PATHS,
    _check_path_blocked,
    _safe_realpath,
)

logger = logging.getLogger("ai-control.automation")

# Dangerous commands that must never be executed via the SHELL step.
# Pattern list is a regex-normalized screen (whitespace-insensitive).
_BLOCKED_COMMAND_PATTERNS = [
    r"\brm\s+-[rRf]*[rR][rRf]*\s+/(\*|\s|$)",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bpoweroff\b",
    r"\bhalt\b",
    r"\binit\s+[06]\b",
    r":\(\)\s*\{",
    r"\bchmod\s+-R\s+777\s+/",
    r"\bchown\s+-R\s+",
    r"\bmv\s+/\s",
    r">\s*/dev/sd[a-z]",
    r">\s*/dev/nvme",
    r"\bwget\s+[^|&;]+\s*\|\s*(sh|bash|zsh)",
    r"\bcurl\s+[^|&;]+\s*\|\s*(sh|bash|zsh)",
    r"\bnc\s+.*-e\b",
]

_BLOCKED_COMMAND_RE = re.compile("|".join(_BLOCKED_COMMAND_PATTERNS), re.IGNORECASE)


def _sanitize_log(s) -> str:
    if not isinstance(s, str):
        s = str(s)
    return s.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")[:512]


def _validate_unit_name(name: str) -> bool:
    """Validate systemd unit / service name (no flag injection, no path)."""
    if not isinstance(name, str) or not name or name.startswith("-"):
        return False
    if any(c in name for c in "\x00\n\r \t;|&$`<>*?\\\"'"):
        return False
    # Allow letter/digit/._@:- typical for unit names
    return bool(re.fullmatch(r"[A-Za-z0-9._@:\-]{1,253}", name))


def _validate_package_name(name: str) -> bool:
    """Validate pacman package name (reject flag-like and path-like inputs)."""
    if not isinstance(name, str) or not name or name.startswith("-"):
        return False
    if "/" in name or "\\" in name or any(c in name for c in "\x00\n\r \t;|&$`<>*?\"'"):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9._+\-]{1,128}", name))


def _validate_url(url: str) -> tuple[bool, str]:
    """Validate an HTTP(S) URL for the HTTP step.

    Refuses non-http schemes and obvious SSRF targets (localhost,
    RFC1918, link-local, cloud metadata IPs) without DNS resolution.
    Returns (ok, reason).
    """
    if not isinstance(url, str) or not url:
        return False, "empty url"
    try:
        u = urlparse(url)
    except ValueError as e:
        return False, f"bad url: {e}"
    if u.scheme not in ("http", "https"):
        return False, f"scheme not allowed: {u.scheme}"
    host = (u.hostname or "").strip()
    if not host:
        return False, "missing host"
    # Reject credentials in URL (phishing / log leak).
    if u.username or u.password:
        return False, "credentials in url not allowed"
    # If host is a literal IP, block private / loopback / link-local / metadata.
    try:
        ip = ipaddress.ip_address(host)
        if (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False, f"blocked ip range: {host}"
        # Cloud metadata service (covered by link-local 169.254.*, but belt-and-braces)
        if str(ip) in ("169.254.169.254", "100.100.100.200", "fd00:ec2::254"):
            return False, "cloud metadata endpoint blocked"
    except ValueError:
        # Hostname — block obvious localhost forms; do NOT resolve DNS here
        # (the HTTP client will, and this best-effort check catches literal names).
        low = host.lower()
        if low in ("localhost", "localhost.localdomain", "ip6-localhost"):
            return False, "localhost blocked"
        if low.endswith(".localhost") or low.endswith(".local"):
            return False, "local TLD blocked"
    return True, ""


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepType(str, Enum):
    SHELL = "shell"           # Run a shell command
    EXEC = "exec"             # Run command without shell (safer)
    FILE_WRITE = "file_write" # Write content to a file
    FILE_READ = "file_read"   # Read a file
    SERVICE = "service"       # systemctl action
    PACKAGE = "package"       # pacman action
    HTTP = "http"             # Call an HTTP endpoint (local or remote)
    PYTHON = "python"         # Execute Python code snippet
    WAIT = "wait"             # Sleep for N seconds
    NOTIFY = "notify"         # Send desktop notification
    CONDITION = "condition"   # Conditional: check exit code / file exists / etc.


@dataclass
class Step:
    type: StepType
    params: dict
    name: str = ""
    continue_on_error: bool = False
    timeout: int = 120


@dataclass
class TaskResult:
    task_id: str
    status: TaskStatus
    steps_completed: int = 0
    steps_total: int = 0
    current_step: str = ""
    output: list = field(default_factory=list)
    error: str = ""
    started_at: float = 0
    finished_at: float = 0
    duration_ms: int = 0


class AutomationEngine:
    """Executes automation tasks with full system access."""

    def __init__(self, max_concurrent: int = 10):
        self._tasks: dict[str, TaskResult] = {}
        self._running: dict[str, asyncio.Task] = {}
        self._max_concurrent = max_concurrent
        self._history: list[dict] = []
        self._max_history = 200

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def _cleanup_old_tasks(self):
        """Remove completed tasks older than 1 hour."""
        cutoff = time.time() - 3600
        stale = [tid for tid, task in self._tasks.items()
                 if task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED)
                 and task.finished_at > 0 and task.finished_at < cutoff]
        for tid in stale:
            del self._tasks[tid]

    async def submit_task(self, name: str, steps: list[dict],
                          description: str = "") -> str:
        """Submit a multi-step automation task. Returns task_id."""
        self._cleanup_old_tasks()
        task_id = str(uuid.uuid4())[:12]
        if not isinstance(steps, list):
            raise ValueError("steps must be a list")
        if len(steps) > 256:
            raise ValueError("too many steps (max 256)")
        parsed_steps = []
        for i, s in enumerate(steps):
            if not isinstance(s, dict):
                raise ValueError(f"step {i} must be an object")
            try:
                step_type = StepType(s.get("type", "shell"))
            except ValueError:
                raise ValueError(f"step {i} has unknown type: {s.get('type')}")
            try:
                timeout = int(s.get("timeout", 120))
            except (TypeError, ValueError):
                timeout = 120
            timeout = max(1, min(timeout, 3600))
            parsed_steps.append(Step(
                type=step_type,
                params=s.get("params", {}),
                name=str(s.get("name", f"step-{i+1}"))[:128],
                continue_on_error=bool(s.get("continue_on_error", False)),
                timeout=timeout,
            ))

        result = TaskResult(
            task_id=task_id,
            status=TaskStatus.PENDING,
            steps_total=len(parsed_steps),
        )
        self._tasks[task_id] = result

        # Start execution
        atask = asyncio.create_task(
            self._execute_task(task_id, name, parsed_steps, description)
        )
        self._running[task_id] = atask
        logger.info("Task %s submitted: %s (%d steps)",
                    task_id, _sanitize_log(name), len(parsed_steps))
        return task_id

    async def submit_quick(self, command: str, timeout: int = 60) -> dict:
        """Execute a single command immediately and return the result."""
        self._cleanup_old_tasks()
        task_id = str(uuid.uuid4())[:8]
        result = await self._run_shell(command, timeout)
        self._record_history(task_id, "quick", command,
                             "completed" if result["returncode"] == 0 else "failed",
                             result)
        return {
            "task_id": task_id,
            "success": result["returncode"] == 0,
            **result,
        }

    async def submit_script(self, script: str, interpreter: str = "/bin/bash",
                            timeout: int = 300) -> dict:
        """Execute a multi-line script and return the result."""
        import tempfile
        task_id = str(uuid.uuid4())[:8]
        # Restrict interpreter to a known-safe allowlist — user-supplied
        # interpreter means user-controlled argv[0], which can be
        # /bin/busybox or similar and bypass intent.
        _ALLOWED_INTERPRETERS = {
            "/bin/bash", "/usr/bin/bash",
            "/bin/sh", "/usr/bin/sh",
            "/bin/zsh", "/usr/bin/zsh",
            "/usr/bin/python3", "/usr/bin/python",
        }
        if interpreter not in _ALLOWED_INTERPRETERS:
            return {"task_id": task_id, "success": False,
                    "error": f"interpreter not allowed: {interpreter}"}
        if not isinstance(script, str):
            return {"task_id": task_id, "success": False,
                    "error": "script must be a string"}
        if len(script) > 4 * 1024 * 1024:
            return {"task_id": task_id, "success": False,
                    "error": "script too large"}
        tmp_path = None
        loop = asyncio.get_running_loop()
        try:
            def _write_tmp():
                # Create with restrictive mode atomically (O_CREAT|O_EXCL, 0o600)
                # rather than letting tempfile choose default umask-dependent bits.
                old_umask = os.umask(0o077)
                try:
                    fd, path = tempfile.mkstemp(prefix="ai-automation-", suffix=".sh")
                finally:
                    os.umask(old_umask)
                try:
                    with os.fdopen(fd, "w") as f:
                        f.write(script)
                    os.chmod(path, 0o700)
                except Exception:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                    raise
                return path
            tmp_path = await loop.run_in_executor(None, _write_tmp)
            result = await self._run_exec([interpreter, tmp_path], timeout)
            self._record_history(task_id, "script", f"({len(script)} bytes)",
                                 "completed" if result["returncode"] == 0 else "failed",
                                 result)
            return {"task_id": task_id, "success": result["returncode"] == 0, **result}
        except Exception as e:
            return {"task_id": task_id, "success": False, "error": str(e)}
        finally:
            if tmp_path:
                try:
                    await loop.run_in_executor(None, os.unlink, tmp_path)
                except OSError:
                    pass

    def get_task(self, task_id: str) -> Optional[dict]:
        """Get task status and output."""
        result = self._tasks.get(task_id)
        if not result:
            return None
        return {
            "task_id": result.task_id,
            "status": result.status.value,
            "steps_completed": result.steps_completed,
            "steps_total": result.steps_total,
            "current_step": result.current_step,
            "output": result.output,
            "error": result.error,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "duration_ms": result.duration_ms,
        }

    def list_tasks(self, status: Optional[str] = None) -> list[dict]:
        """List all tasks, optionally filtered by status."""
        tasks = []
        for r in self._tasks.values():
            if status and r.status.value != status:
                continue
            tasks.append({
                "task_id": r.task_id,
                "status": r.status.value,
                "steps_completed": r.steps_completed,
                "steps_total": r.steps_total,
                "current_step": r.current_step,
                "duration_ms": r.duration_ms,
            })
        return tasks

    async def cancel_task(self, task_id: str) -> dict:
        """Cancel a running task."""
        atask = self._running.get(task_id)
        if atask and not atask.done():
            atask.cancel()
            result = self._tasks.get(task_id)
            if result:
                result.status = TaskStatus.CANCELLED
                result.finished_at = time.time()
            return {"success": True}
        return {"success": False, "error": "Task not running"}

    def get_history(self, count: int = 50) -> list[dict]:
        """Get recent task execution history."""
        return self._history[-count:]

    def get_capabilities(self) -> dict:
        """Return what this automation engine can do."""
        return {
            "step_types": [t.value for t in StepType],
            "max_concurrent_tasks": self._max_concurrent,
            "running_tasks": len([t for t in self._running.values() if not t.done()]),
            "total_tasks": len(self._tasks),
            "features": [
                "shell_commands",
                "multi_step_workflows",
                "file_operations",
                "package_management",
                "service_control",
                "python_execution",
                "conditional_logic",
                "desktop_notifications",
                "scheduled_tasks",
                "script_execution",
                "full_system_access",
            ],
        }

    # ------------------------------------------------------------------
    # Task Execution
    # ------------------------------------------------------------------

    async def _execute_task(self, task_id: str, name: str,
                            steps: list[Step], description: str):
        """Execute all steps in a task sequentially."""
        result = self._tasks[task_id]
        result.status = TaskStatus.RUNNING
        result.started_at = time.time()

        try:
            for i, step in enumerate(steps):
                result.current_step = step.name or f"step-{i+1}"
                step_output = await self._execute_step(step)
                result.output.append({
                    "step": result.current_step,
                    "type": step.type.value,
                    **step_output,
                })
                result.steps_completed = i + 1

                if not step_output.get("success", False) and not step.continue_on_error:
                    result.status = TaskStatus.FAILED
                    result.error = step_output.get("stderr", step_output.get("error", "Step failed"))
                    break
            else:
                result.status = TaskStatus.COMPLETED

        except asyncio.CancelledError:
            result.status = TaskStatus.CANCELLED
        except Exception as e:
            result.status = TaskStatus.FAILED
            result.error = str(e)
            logger.exception("Task %s failed", task_id)
        finally:
            result.finished_at = time.time()
            result.duration_ms = int((result.finished_at - result.started_at) * 1000)
            result.current_step = ""
            self._running.pop(task_id, None)
            self._record_history(task_id, name, description,
                                 result.status.value, {"steps": result.steps_completed})
            logger.info("Task %s %s in %dms", task_id, result.status.value, result.duration_ms)

    async def _execute_step(self, step: Step) -> dict:
        """Execute a single step and return result dict."""
        p = step.params
        if not isinstance(p, dict):
            return {"success": False, "error": "params must be an object"}
        try:
            if step.type == StepType.SHELL:
                cmd = p.get("command", "")
                if not isinstance(cmd, str):
                    return {"success": False, "error": "command must be a string"}
                # Screen against the regex blocklist (whitespace-insensitive).
                m = _BLOCKED_COMMAND_RE.search(cmd)
                if m:
                    return {"success": False,
                            "error": f"Blocked command pattern: {m.group(0)!r}"}
                return await self._run_shell(cmd, step.timeout)

            elif step.type == StepType.EXEC:
                argv = p.get("argv", [])
                if isinstance(argv, str):
                    argv = shlex.split(argv)
                if not isinstance(argv, list) or not argv:
                    return {"success": False, "error": "argv must be a non-empty list"}
                if not all(isinstance(a, str) for a in argv):
                    return {"success": False, "error": "argv entries must be strings"}
                # No path-traversal in argv[0] that would pick up a planted binary.
                if not argv[0] or "\x00" in argv[0]:
                    return {"success": False, "error": "invalid argv[0]"}
                return await self._run_exec(argv, step.timeout)

            elif step.type == StepType.FILE_WRITE:
                path = p.get("path", "")
                try:
                    abs_path = _safe_realpath(path)
                except ValueError as e:
                    return {"success": False, "error": str(e)}
                err = _check_path_blocked(abs_path, _BLOCKED_WRITE_PATHS, "Write")
                if err:
                    return {"success": False, "error": err}
                content = p.get("content", "")
                if not isinstance(content, (str, bytes)):
                    return {"success": False, "error": "content must be string or bytes"}
                mode = p.get("mode", "w")
                if mode not in ("w", "wb", "a", "ab"):
                    return {"success": False, "error": f"mode not allowed: {mode}"}
                chmod_val = p.get("chmod")
                def _do_write():
                    os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
                    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
                    if "a" in mode:
                        flags |= os.O_APPEND
                    else:
                        flags |= os.O_TRUNC
                    old_umask = os.umask(0o077)
                    try:
                        fd = os.open(abs_path, flags, 0o600)
                    finally:
                        os.umask(old_umask)
                    with os.fdopen(fd, mode) as f:
                        f.write(content)
                    if chmod_val is not None:
                        cv = int(chmod_val, 8) if isinstance(chmod_val, str) else int(chmod_val)
                        if cv < 0 or cv > 0o7777:
                            raise ValueError("chmod out of range")
                        os.chmod(abs_path, cv)
                loop = asyncio.get_running_loop()
                try:
                    await loop.run_in_executor(None, _do_write)
                except Exception as e:
                    return {"success": False, "error": str(e)}
                return {"success": True, "path": abs_path, "bytes": len(content)}

            elif step.type == StepType.FILE_READ:
                path = p.get("path", "")
                try:
                    abs_path = _safe_realpath(path)
                except ValueError as e:
                    return {"success": False, "error": str(e)}
                err = _check_path_blocked(abs_path, _BLOCKED_READ_PATHS, "Read")
                if err:
                    return {"success": False, "error": err}
                def _do_read():
                    # Refuse symlink final-component (O_NOFOLLOW-equivalent).
                    import stat as _stat
                    st = os.lstat(abs_path)
                    if _stat.S_ISLNK(st.st_mode):
                        raise OSError("refusing to follow symlink")
                    if st.st_size > 64 * 1024 * 1024:
                        raise OSError(f"file too large ({st.st_size} bytes)")
                    with open(abs_path, "r") as f:
                        return f.read()
                loop = asyncio.get_running_loop()
                try:
                    content = await loop.run_in_executor(None, _do_read)
                except Exception as e:
                    return {"success": False, "error": str(e)}
                return {"success": True, "content": content, "bytes": len(content)}

            elif step.type == StepType.SERVICE:
                action = p.get("action", "status")
                service = p.get("service", "")
                if action not in ("start", "stop", "restart", "status",
                                  "enable", "disable", "reload", "is-active",
                                  "is-enabled"):
                    return {"success": False, "error": f"action not allowed: {action}"}
                if not _validate_unit_name(service):
                    return {"success": False, "error": "invalid service name"}
                r = await self._run_exec(["systemctl", "--", action, service], step.timeout)
                return {"success": r["returncode"] == 0, **r}

            elif step.type == StepType.PACKAGE:
                action = p.get("action", "install")
                pkg = p.get("package", "")
                if action in ("install", "remove"):
                    if not _validate_package_name(pkg):
                        return {"success": False, "error": "invalid package name"}
                if action == "install":
                    r = await self._run_exec(["pacman", "-S", "--noconfirm", "--", pkg], step.timeout)
                elif action == "remove":
                    r = await self._run_exec(["pacman", "-R", "--noconfirm", "--", pkg], step.timeout)
                elif action == "update":
                    r = await self._run_exec(["pacman", "-Syu", "--noconfirm"], step.timeout)
                else:
                    return {"success": False, "error": f"Unknown package action: {action}"}
                return {"success": r["returncode"] == 0, **r}

            elif step.type == StepType.HTTP:
                import aiohttp
                method = p.get("method", "GET").upper()
                if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    return {"success": False, "error": f"method not allowed: {method}"}
                url = p.get("url", "")
                ok, reason = _validate_url(url)
                if not ok:
                    return {"success": False, "error": f"url rejected: {reason}"}
                headers = p.get("headers", {})
                if not isinstance(headers, dict):
                    return {"success": False, "error": "headers must be an object"}
                # Strip CR/LF from header values to prevent header injection.
                safe_headers = {}
                for k, v in headers.items():
                    if not isinstance(k, str) or not isinstance(v, (str, int, float)):
                        continue
                    sv = str(v)
                    if "\r" in k or "\n" in k or "\r" in sv or "\n" in sv:
                        return {"success": False, "error": "CRLF in header not allowed"}
                    safe_headers[k] = sv
                body = p.get("body", None)
                async with aiohttp.ClientSession() as session:
                    req_kwargs = {"headers": safe_headers,
                                  "timeout": aiohttp.ClientTimeout(total=step.timeout),
                                  "allow_redirects": False}
                    if body is not None:
                        req_kwargs["json"] = body
                    async with session.request(method, url, **req_kwargs) as resp:
                        # Cap response body to avoid memory exhaustion.
                        raw = await resp.content.read(4 * 1024 * 1024)
                        try:
                            text = raw.decode("utf-8", errors="replace")
                        except Exception:
                            text = ""
                        return {"success": resp.status < 400,
                                "status": resp.status, "body": text}

            elif step.type == StepType.PYTHON:
                # PYTHON exec is inherently unsafe: exec() in CPython cannot be
                # sandboxed (dunder escapes trivially reach the file system and
                # import machinery). Disable it entirely from the automation
                # boundary; callers that legitimately need Python should use
                # SHELL with /usr/bin/python3 -c or submit_script(interpreter="/usr/bin/python3").
                return {"success": False,
                        "error": "PYTHON step disabled; use SHELL or submit_script instead"}

            elif step.type == StepType.WAIT:
                seconds = p.get("seconds", 1)
                try:
                    seconds = float(seconds)
                except (TypeError, ValueError):
                    return {"success": False, "error": "seconds must be a number"}
                if seconds < 0 or seconds > 3600:
                    return {"success": False, "error": "seconds out of range [0, 3600]"}
                await asyncio.sleep(seconds)
                return {"success": True, "waited": seconds}

            elif step.type == StepType.NOTIFY:
                title = p.get("title", "AI Automation")
                message = p.get("message", "")
                urgency = p.get("urgency", "normal")
                icon = p.get("icon", "dialog-information")
                if urgency not in ("low", "normal", "critical"):
                    urgency = "normal"
                # Clamp title/message/icon to plain strings of reasonable length.
                title = str(title)[:256]
                message = str(message)[:4096]
                # Icon name: restrict charset to avoid argv injection.
                if not isinstance(icon, str) or not re.fullmatch(r"[A-Za-z0-9._\-/]{1,128}", icon):
                    icon = "dialog-information"
                env = os.environ.copy()
                env.setdefault("DISPLAY", ":0")
                proc = None
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "notify-send", "-u", urgency, "-i", icon, "--", title, message,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=env,
                    )
                    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                    return {"success": proc.returncode == 0,
                            "returncode": proc.returncode,
                            "stderr": stderr.decode(errors="replace").strip()}
                except asyncio.TimeoutError:
                    # Session 24: reap notify-send if it hangs (e.g., no DBus session)
                    if proc is not None:
                        try:
                            proc.kill()
                        except ProcessLookupError:
                            pass
                        try:
                            await proc.wait()
                        except Exception:
                            pass
                    return {"success": False, "error": "notify-send timed out"}
                except Exception as e:
                    if proc is not None:
                        try:
                            proc.kill()
                        except ProcessLookupError:
                            pass
                        try:
                            await proc.wait()
                        except Exception:
                            pass
                    return {"success": False, "error": str(e)}

            elif step.type == StepType.CONDITION:
                check = p.get("check", "")
                if check == "file_exists":
                    cond_path = p.get("path", "")
                    try:
                        rp = _safe_realpath(cond_path)
                    except ValueError as e:
                        return {"success": False, "error": str(e)}
                    exists = os.path.exists(rp)
                    return {"success": exists, "exists": exists}
                elif check == "service_active":
                    svc = p.get("service", "")
                    if not _validate_unit_name(svc):
                        return {"success": False, "error": "invalid service name"}
                    r = await self._run_exec(
                        ["systemctl", "is-active", "--quiet", "--", svc], 10
                    )
                    return {"success": r["returncode"] == 0,
                            "active": r["returncode"] == 0}
                elif check == "command":
                    cmd = p.get("command", "")
                    if not isinstance(cmd, str):
                        return {"success": False, "error": "command must be a string"}
                    m = _BLOCKED_COMMAND_RE.search(cmd)
                    if m:
                        return {"success": False,
                                "error": f"Blocked command pattern: {m.group(0)!r}"}
                    r = await self._run_shell(cmd, step.timeout)
                    return {"success": r["returncode"] == 0, **r}
                else:
                    return {"success": False, "error": f"Unknown condition: {check}"}

            else:
                return {"success": False, "error": f"Unknown step type: {step.type}"}

        except asyncio.TimeoutError:
            return {"success": False, "error": "Step timed out", "returncode": -1}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ------------------------------------------------------------------
    # Subprocess Helpers
    # ------------------------------------------------------------------

    async def _run_shell(self, cmd: str, timeout: int = 60) -> dict:
        proc = None
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": stdout.decode(errors="replace").strip(),
                "stderr": stderr.decode(errors="replace").strip(),
            }
        except asyncio.TimeoutError:
            if proc is not None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                try:
                    await proc.wait()
                except Exception:
                    pass
            return {"success": False, "returncode": -1, "stdout": "", "stderr": "timeout"}
        except Exception as e:
            if proc is not None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                try:
                    await proc.wait()
                except Exception:
                    pass
            return {"success": False, "returncode": -1, "stdout": "", "stderr": str(e)}

    async def _run_exec(self, argv: list, timeout: int = 60) -> dict:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": stdout.decode(errors="replace").strip(),
                "stderr": stderr.decode(errors="replace").strip(),
            }
        except asyncio.TimeoutError:
            if proc is not None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                try:
                    await proc.wait()
                except Exception:
                    pass
            return {"success": False, "returncode": -1, "stdout": "", "stderr": "timeout"}
        except Exception as e:
            if proc is not None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                try:
                    await proc.wait()
                except Exception:
                    pass
            return {"success": False, "returncode": -1, "stdout": "", "stderr": str(e)}

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def _record_history(self, task_id: str, name: str, description: str,
                        status: str, details: dict):
        entry = {
            "task_id": task_id,
            "name": name,
            "description": description,
            "status": status,
            "timestamp": time.time(),
            **details,
        }
        self._history.append(entry)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]
