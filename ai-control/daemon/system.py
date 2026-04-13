"""
System control module - full system management capabilities.

Provides:
- Package management (pacman)
- Service control (systemd)
- Process management
- System information

All subprocess operations are async to avoid blocking the FastAPI event loop.
"""

import asyncio
import logging
import os
import signal

logger = logging.getLogger("ai-control.system")


async def _run_async(*args, timeout: int = 30, shell: bool = False) -> dict:
    """Run a subprocess asynchronously and return result dict."""
    try:
        if shell:
            proc = await asyncio.create_subprocess_shell(
                args[0],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return {
            "returncode": proc.returncode,
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
        }
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()  # Reap the killed process to prevent zombies
        return {"returncode": -1, "stdout": "", "stderr": "timeout"}
    except FileNotFoundError as exc:
        return {"returncode": -1, "stdout": "", "stderr": str(exc)}


class SystemController:
    """Full system control running as root."""

    def __init__(self):
        self.is_root = os.geteuid() == 0

    # --- Package Management ---

    async def install_package(self, package: str) -> dict:
        r = await _run_async("pacman", "-S", "--noconfirm", package, timeout=300)
        return {"success": r["returncode"] == 0, "stdout": r["stdout"], "stderr": r["stderr"]}

    async def remove_package(self, package: str) -> dict:
        r = await _run_async("pacman", "-R", "--noconfirm", package, timeout=120)
        return {"success": r["returncode"] == 0, "stdout": r["stdout"], "stderr": r["stderr"]}

    async def update_system(self) -> dict:
        r = await _run_async("pacman", "-Syu", "--noconfirm", timeout=600)
        return {"success": r["returncode"] == 0, "stdout": r["stdout"], "stderr": r["stderr"]}

    async def search_packages(self, query: str) -> dict:
        r = await _run_async("pacman", "-Ss", query, timeout=30)
        return {"success": r["returncode"] == 0, "results": r["stdout"]}

    async def list_installed(self) -> list[str]:
        r = await _run_async("pacman", "-Q", timeout=30)
        if r["returncode"] == 0:
            return r["stdout"].strip().split("\n")
        return []

    # --- Update Checking ---

    async def check_updates(self) -> list[dict]:
        """Check for available package updates using checkupdates (pacman-contrib)."""
        r = await _run_async("checkupdates", timeout=60)
        updates = []
        if r["returncode"] == 0:
            for line in r["stdout"].strip().split("\n"):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        updates.append({
                            "package": parts[0],
                            "current": parts[1],
                            "new": parts[3],
                        })
        return updates

    # --- Service Control ---

    async def start_service(self, service: str) -> dict:
        r = await _run_async("systemctl", "start", service, timeout=30)
        return {"success": r["returncode"] == 0, "stderr": r["stderr"]}

    async def stop_service(self, service: str) -> dict:
        r = await _run_async("systemctl", "stop", service, timeout=30)
        return {"success": r["returncode"] == 0, "stderr": r["stderr"]}

    async def restart_service(self, service: str) -> dict:
        r = await _run_async("systemctl", "restart", service, timeout=30)
        return {"success": r["returncode"] == 0, "stderr": r["stderr"]}

    async def enable_service(self, service: str) -> dict:
        r = await _run_async("systemctl", "enable", service, timeout=30)
        return {"success": r["returncode"] == 0, "stderr": r["stderr"]}

    async def service_status(self, service: str) -> dict:
        r = await _run_async("systemctl", "status", service, timeout=10)
        return {"active": r["returncode"] == 0, "output": r["stdout"]}

    async def list_services(self) -> list[dict]:
        r = await _run_async(
            "systemctl", "list-units", "--type=service", "--no-pager",
            "--plain", "--no-legend", timeout=10
        )
        services = []
        for line in r["stdout"].strip().split("\n"):
            parts = line.split(None, 4)
            if len(parts) >= 4:
                services.append({
                    "unit": parts[0],
                    "load": parts[1],
                    "active": parts[2],
                    "sub": parts[3],
                    "description": parts[4] if len(parts) > 4 else "",
                })
        return services

    # --- Process Management ---

    async def list_processes(self) -> list[dict]:
        r = await _run_async("ps", "aux", "--no-headers", timeout=10)
        processes = []
        for line in r["stdout"].strip().split("\n"):
            parts = line.split(None, 10)
            if len(parts) >= 11:
                try:
                    processes.append({
                        "user": parts[0],
                        "pid": int(parts[1]),
                        "cpu": float(parts[2]),
                        "mem": float(parts[3]),
                        "command": parts[10],
                    })
                except (ValueError, IndexError):
                    continue
        return processes

    def kill_process(self, pid: int, sig: int = signal.SIGTERM) -> bool:
        try:
            os.kill(pid, sig)
            return True
        except (ProcessLookupError, PermissionError):
            return False

    async def run_command(self, command: str, timeout: int = 60) -> dict:
        import shlex
        try:
            args = shlex.split(command)
        except ValueError as e:
            return {"status": "error", "error": f"Invalid command syntax: {e}", "returncode": -1, "stdout": "", "stderr": ""}
        r = await _run_async(*args, timeout=timeout, shell=False)
        return {"returncode": r["returncode"], "stdout": r["stdout"], "stderr": r["stderr"]}

    # --- System Information ---

    async def get_system_info(self) -> dict:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._get_system_info_sync)

    def _get_system_info_sync(self) -> dict:
        info = {}
        info["hostname"] = os.uname().nodename
        info["kernel"] = os.uname().release

        try:
            with open("/proc/uptime", "r") as f:
                info["uptime_seconds"] = float(f.read().split()[0])
        except OSError:
            info["uptime_seconds"] = 0

        try:
            with open("/proc/meminfo", "r") as f:
                meminfo = {}
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().split()[0]
                        meminfo[key] = int(val)
                info["memory"] = {
                    "total_kb": meminfo.get("MemTotal", 0),
                    "available_kb": meminfo.get("MemAvailable", 0),
                    "free_kb": meminfo.get("MemFree", 0),
                }
        except OSError:
            info["memory"] = {"total_kb": 0, "available_kb": 0, "free_kb": 0}

        info["cpu_count"] = os.cpu_count() or 1

        try:
            load1, load5, load15 = os.getloadavg()
            info["load_average"] = {"1m": load1, "5m": load5, "15m": load15}
        except OSError:
            info["load_average"] = {"1m": 0, "5m": 0, "15m": 0}

        try:
            stat = os.statvfs("/")
            info["disk"] = {
                "total_bytes": stat.f_blocks * stat.f_frsize,
                "free_bytes": stat.f_bfree * stat.f_frsize,
                "available_bytes": stat.f_bavail * stat.f_frsize,
            }
        except OSError:
            info["disk"] = {"total_bytes": 0, "free_bytes": 0, "available_bytes": 0}

        return info
