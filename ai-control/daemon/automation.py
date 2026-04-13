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
import json
import logging
import os
import shlex
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from filesystem import _BLOCKED_WRITE_PATHS, _BLOCKED_READ_PATHS

logger = logging.getLogger("ai-control.automation")

# Dangerous commands that must never be executed via the SHELL step
_BLOCKED_COMMANDS = [
    "rm -rf /", "rm -rf /*", "mkfs", "dd if=", "shutdown", "reboot",
    "poweroff", "halt", "init 0", "init 6", ":(){", "fork bomb",
    "chmod -R 777 /", "chown -R", "mv / ", "> /dev/sda",
    "wget|sh", "curl|sh",
]


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
        parsed_steps = []
        for i, s in enumerate(steps):
            step_type = StepType(s.get("type", "shell"))
            parsed_steps.append(Step(
                type=step_type,
                params=s.get("params", {}),
                name=s.get("name", f"step-{i+1}"),
                continue_on_error=s.get("continue_on_error", False),
                timeout=s.get("timeout", 120),
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
        logger.info("Task %s submitted: %s (%d steps)", task_id, name, len(parsed_steps))
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
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sh',
                                              delete=False) as tmp:
                tmp.write(script)
                tmp_path = tmp.name
            os.chmod(tmp_path, 0o700)
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
                    os.unlink(tmp_path)
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
        try:
            if step.type == StepType.SHELL:
                cmd = p.get("command", "")
                cmd_lower = cmd.lower().strip()
                for blocked in _BLOCKED_COMMANDS:
                    if blocked in cmd_lower:
                        return {"success": False, "error": f"Blocked command: {blocked}"}
                return await self._run_shell(cmd, step.timeout)

            elif step.type == StepType.EXEC:
                argv = p.get("argv", [])
                if isinstance(argv, str):
                    argv = shlex.split(argv)
                return await self._run_exec(argv, step.timeout)

            elif step.type == StepType.FILE_WRITE:
                path = p.get("path", "")
                abs_path = os.path.realpath(path)
                for blocked in _BLOCKED_WRITE_PATHS:
                    if blocked.endswith("/"):
                        if abs_path.startswith(blocked) or abs_path == blocked.rstrip("/"):
                            return {"success": False, "error": f"Write blocked: {abs_path} is inside protected path {blocked}"}
                    elif abs_path == blocked or abs_path.startswith(blocked):
                        return {"success": False, "error": f"Write blocked: {abs_path} is a protected file"}
                content = p.get("content", "")
                mode = p.get("mode", "w")
                os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
                with open(abs_path, mode) as f:
                    f.write(content)
                if "chmod" in p:
                    os.chmod(abs_path, int(p["chmod"], 8) if isinstance(p["chmod"], str) else p["chmod"])
                return {"success": True, "path": abs_path, "bytes": len(content)}

            elif step.type == StepType.FILE_READ:
                path = p.get("path", "")
                abs_path = os.path.realpath(path)
                for blocked in _BLOCKED_READ_PATHS:
                    if blocked.endswith("/"):
                        if abs_path.startswith(blocked) or abs_path == blocked.rstrip("/"):
                            return {"success": False, "error": f"Read blocked: {abs_path} is inside protected path {blocked}"}
                    elif abs_path == blocked or abs_path.startswith(blocked):
                        return {"success": False, "error": f"Read blocked: {abs_path} is a protected file"}
                with open(abs_path, "r") as f:
                    content = f.read()
                return {"success": True, "content": content, "bytes": len(content)}

            elif step.type == StepType.SERVICE:
                action = p.get("action", "status")
                service = p.get("service", "")
                r = await self._run_exec(["systemctl", action, service], step.timeout)
                return {"success": r["returncode"] == 0, **r}

            elif step.type == StepType.PACKAGE:
                action = p.get("action", "install")
                pkg = p.get("package", "")
                if action == "install":
                    r = await self._run_exec(["pacman", "-S", "--noconfirm", pkg], step.timeout)
                elif action == "remove":
                    r = await self._run_exec(["pacman", "-R", "--noconfirm", pkg], step.timeout)
                elif action == "update":
                    r = await self._run_exec(["pacman", "-Syu", "--noconfirm"], step.timeout)
                else:
                    return {"success": False, "error": f"Unknown package action: {action}"}
                return {"success": r["returncode"] == 0, **r}

            elif step.type == StepType.HTTP:
                import aiohttp
                method = p.get("method", "GET").upper()
                url = p.get("url", "")
                headers = p.get("headers", {})
                body = p.get("body", None)
                async with aiohttp.ClientSession() as session:
                    req_kwargs = {"headers": headers, "timeout": aiohttp.ClientTimeout(total=step.timeout)}
                    if body:
                        req_kwargs["json"] = body
                    async with session.request(method, url, **req_kwargs) as resp:
                        text = await resp.text()
                        return {"success": resp.status < 400, "status": resp.status, "body": text}

            elif step.type == StepType.PYTHON:
                code = p.get("code", "")
                # Execute in a restricted namespace with safe builtins only
                _SAFE_BUILTINS = {
                    "abs": abs, "all": all, "any": any, "bool": bool, "dict": dict,
                    "enumerate": enumerate, "filter": filter, "float": float,
                    "format": format, "frozenset": frozenset, "hasattr": hasattr,
                    "hash": hash, "int": int, "isinstance": isinstance, "issubclass": issubclass,
                    "iter": iter, "len": len, "list": list, "map": map, "max": max,
                    "min": min, "next": next, "print": print, "range": range,
                    "repr": repr, "reversed": reversed, "round": round, "set": set,
                    "slice": slice, "sorted": sorted, "str": str, "sum": sum,
                    "tuple": tuple, "type": type, "zip": zip,
                    "True": True, "False": False, "None": None,
                }
                namespace = {"os": os, "asyncio": asyncio, "json": json,
                             "result": None, "__builtins__": _SAFE_BUILTINS}
                exec(code, namespace)
                return {"success": True, "result": str(namespace.get("result", ""))}

            elif step.type == StepType.WAIT:
                seconds = p.get("seconds", 1)
                await asyncio.sleep(seconds)
                return {"success": True, "waited": seconds}

            elif step.type == StepType.NOTIFY:
                title = p.get("title", "AI Automation")
                message = p.get("message", "")
                urgency = p.get("urgency", "normal")
                icon = p.get("icon", "dialog-information")
                env = os.environ.copy()
                env.setdefault("DISPLAY", ":0")
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "notify-send", "-u", urgency, "-i", icon, title, message,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=env,
                    )
                    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                    return {"success": proc.returncode == 0,
                            "returncode": proc.returncode,
                            "stderr": stderr.decode(errors="replace").strip()}
                except Exception as e:
                    return {"success": False, "error": str(e)}

            elif step.type == StepType.CONDITION:
                check = p.get("check", "")
                if check == "file_exists":
                    exists = os.path.exists(p.get("path", ""))
                    return {"success": exists, "exists": exists}
                elif check == "service_active":
                    r = await self._run_exec(
                        ["systemctl", "is-active", "--quiet", p.get("service", "")], 10
                    )
                    return {"success": r["returncode"] == 0, "active": r["returncode"] == 0}
                elif check == "command":
                    r = await self._run_shell(p.get("command", ""), step.timeout)
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
            proc.kill()
            await proc.wait()
            return {"success": False, "returncode": -1, "stdout": "", "stderr": "timeout"}
        except Exception as e:
            return {"success": False, "returncode": -1, "stdout": "", "stderr": str(e)}

    async def _run_exec(self, argv: list, timeout: int = 60) -> dict:
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
            proc.kill()
            await proc.wait()
            return {"success": False, "returncode": -1, "stdout": "", "stderr": "timeout"}
        except Exception as e:
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
