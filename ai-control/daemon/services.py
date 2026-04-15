"""
Windows Service Control bridge for the AI daemon.

Provides an interface to query and control services managed by
the SCM (Service Control Manager) daemon.  Communicates with
scm_daemon over its UNIX domain socket or via direct CLI invocation.

All subprocess operations are async to avoid blocking the FastAPI event loop.
"""

import asyncio
import logging
import os
import shlex
from typing import Optional

logger = logging.getLogger("ai-control.services")

SCM_SOCKET = "/run/pe-compat/scm.sock"
SC_BIN = "/usr/bin/sc"


class WindowsServiceController:
    """AI-facing controller for Windows services managed by the SCM."""

    def __init__(self, sc_bin: str = SC_BIN) -> None:
        self._sc_bin = sc_bin

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    async def list_services(self) -> dict:
        return await self._sc("query")

    async def get_service(self, name: str) -> dict:
        return await self._sc(f"query {shlex.quote(name)}")

    async def get_service_details(self, name: str) -> dict:
        """Get comprehensive details for a single Windows service.

        Queries the SCM daemon for full service metadata including
        display name, description, start type, dependencies, PID, and uptime.
        """
        # qc = query config, query = runtime state
        config_result = await self._sc(f"qc {shlex.quote(name)}")
        state_result = await self._sc(f"query {shlex.quote(name)}")

        details: dict = {
            "name": name,
            "display_name": name,
            "description": "",
            "type": "unknown",
            "state": "unknown",
            "pid": 0,
            "start_type": "unknown",
            "dependencies": [],
            "dependent_services": [],
            "exe_path": "",
            "uptime": None,
        }

        # Parse config output (qc)
        if config_result.get("success"):
            for line in config_result.get("stdout", "").split("\n"):
                line = line.strip()
                if line.startswith("DISPLAY_NAME") or line.startswith("DisplayName"):
                    details["display_name"] = line.split(":", 1)[-1].strip() or name
                elif line.startswith("BINARY_PATH_NAME") or line.startswith("binPath"):
                    details["exe_path"] = line.split(":", 1)[-1].strip()
                elif line.startswith("START_TYPE") or line.startswith("start"):
                    raw = line.split(":", 1)[-1].strip().lower()
                    if "auto" in raw:
                        details["start_type"] = "auto"
                    elif "demand" in raw or "manual" in raw:
                        details["start_type"] = "manual"
                    elif "disabled" in raw:
                        details["start_type"] = "disabled"
                    else:
                        details["start_type"] = raw
                elif line.startswith("DEPENDENCIES") or line.startswith("depend"):
                    deps = line.split(":", 1)[-1].strip()
                    if deps:
                        details["dependencies"] = [d.strip() for d in deps.split("/") if d.strip()]
                elif line.startswith("DESCRIPTION") or line.startswith("description"):
                    details["description"] = line.split(":", 1)[-1].strip()

        # Parse state output (query)
        if state_result.get("success"):
            for line in state_result.get("stdout", "").split("\n"):
                line = line.strip()
                if "STATE" in line:
                    state_str = line.split(":", 1)[-1].strip().lower()
                    if "running" in state_str:
                        details["state"] = "running"
                    elif "stopped" in state_str:
                        details["state"] = "stopped"
                    elif "start_pending" in state_str or "starting" in state_str:
                        details["state"] = "start_pending"
                    elif "stop_pending" in state_str or "stopping" in state_str:
                        details["state"] = "stop_pending"
                    else:
                        details["state"] = state_str
                elif "PID" in line:
                    try:
                        details["pid"] = int(line.split(":", 1)[-1].strip())
                    except (ValueError, IndexError):
                        pass
                elif "TYPE" in line and "SERVICE_TYPE" not in line.upper().replace(" ", "_"):
                    details["type"] = line.split(":", 1)[-1].strip()

        # Try to get uptime from /proc if PID is available
        if details["pid"] > 0:
            try:
                with open(f"/proc/{details['pid']}/stat", "r") as f:
                    stat_line = f.read()
                # field 22 (1-indexed) is starttime in clock ticks since boot.
                # comm (field 2) may contain spaces/parens; split after last ')'.
                rparen = stat_line.rfind(")")
                if rparen != -1:
                    fields = stat_line[rparen + 1:].split()
                    # Overall field 22 -> fields[19] (0-indexed, post-comm)
                    if len(fields) > 19:
                        starttime_ticks = int(fields[19])
                        with open("/proc/uptime", "r") as uf:
                            uptime_seconds = float(uf.read().split()[0])
                        try:
                            clk_tck = os.sysconf("SC_CLK_TCK")
                        except (ValueError, OSError):
                            clk_tck = 100
                        proc_uptime = int(uptime_seconds - (starttime_ticks / clk_tck))
                        if proc_uptime >= 0:
                            details["uptime"] = proc_uptime
            except (FileNotFoundError, ProcessLookupError, ValueError, IndexError, PermissionError):
                pass

        return {"status": "ok", "service": details}

    async def get_service_logs(self, name: str, lines: int = 50) -> dict:
        """Get recent log output for a Windows service from journald.

        Falls back to searching for the service name in syslog if
        the unit isn't known to systemd.
        """
        lines = min(max(lines, 1), 500)  # clamp to 1..500
        proc = None
        proc2 = None
        try:
            # First try exact unit match
            proc = await asyncio.create_subprocess_exec(
                "journalctl", "-u", name, "-n", str(lines), "--no-pager",
                "--output=short-iso",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode(errors="replace").strip()

            # If no output from unit, try grep-based search
            if not output or "No entries" in output or "-- No entries --" in output:
                proc2 = await asyncio.create_subprocess_exec(
                    "journalctl", "-t", f"scm-daemon", "-n", str(lines),
                    "--no-pager", "--output=short-iso",
                    "--grep", name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=10)
                output = stdout2.decode(errors="replace").strip()

            log_lines = output.split("\n") if output else []
            return {
                "status": "ok",
                "service": name,
                "lines": log_lines,
                "count": len(log_lines),
            }
        except asyncio.TimeoutError:
            for p in (proc, proc2):
                if p is not None:
                    try:
                        p.kill()
                        await p.wait()
                    except Exception:
                        pass
            return {"status": "error", "error": "timeout reading logs"}
        except FileNotFoundError:
            return {"status": "error", "error": "journalctl not found"}

    async def restart_service(self, name: str) -> dict:
        """Restart a Windows service by stopping then starting it."""
        stop_result = await self.stop_service(name)
        # Brief pause to let the SCM daemon process the stop
        await asyncio.sleep(0.5)
        start_result = await self.start_service(name)
        return {
            "status": "ok",
            "stop": stop_result,
            "start": start_result,
            "success": start_result.get("success", False),
        }

    # ------------------------------------------------------------------
    # Control
    # ------------------------------------------------------------------

    async def start_service(self, name: str) -> dict:
        return await self._sc(f"start {shlex.quote(name)}")

    async def stop_service(self, name: str) -> dict:
        return await self._sc(f"stop {shlex.quote(name)}")

    async def install_service(
        self,
        name: str,
        binary_path: str,
        display_name: Optional[str] = None,
        start_type: str = "auto",
    ) -> dict:
        cmd = f'create {shlex.quote(name)} binPath= {shlex.quote(binary_path)}'
        if display_name:
            cmd += f' DisplayName= {shlex.quote(display_name)}'
        cmd += f" start= {shlex.quote(start_type)}"
        return await self._sc(cmd)

    async def delete_service(self, name: str) -> dict:
        return await self._sc(f"delete {shlex.quote(name)}")

    # ------------------------------------------------------------------
    # SCM daemon control
    # ------------------------------------------------------------------

    async def scm_status(self) -> dict:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl", "is-active", "scm-daemon.service",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            status = stdout.decode().strip()
            return {"running": status == "active", "status": status}
        except asyncio.TimeoutError:
            if proc is not None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return {"running": False, "error": "timeout"}
        except FileNotFoundError as exc:
            return {"running": False, "error": str(exc)}

    async def scm_restart(self) -> dict:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl", "restart", "scm-daemon.service",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            return {
                "success": proc.returncode == 0,
                "stderr": stderr.decode().strip(),
            }
        except asyncio.TimeoutError:
            if proc is not None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return {"success": False, "error": "timeout"}
        except FileNotFoundError as exc:
            return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _sc(self, args: str) -> dict:
        argv = [self._sc_bin] + shlex.split(args)
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
            return {
                "success": proc.returncode == 0,
                "stdout": stdout.decode(errors="replace").strip(),
                "stderr": stderr.decode(errors="replace").strip(),
                "returncode": proc.returncode,
            }
        except asyncio.TimeoutError:
            logger.error("sc command timed out: %s", argv)
            if proc is not None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return {"success": False, "error": "timeout"}
        except FileNotFoundError:
            logger.error("sc binary not found at %s", self._sc_bin)
            return {"success": False, "error": f"{self._sc_bin} not found"}
