"""
Desktop Automation - AI-controlled desktop management.

Provides:
- Application launching and management
- Window management (position, size, focus, minimize, maximize)
- Desktop shortcut creation and management
- Game scanning, installation, and launching
- Scheduled task management
- Clipboard operations
- Notification sending
"""

import asyncio
import json
import logging
import os
import shlex
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ai-control.desktop")


async def _run_exec(argv: list[str], timeout: int = 30,
                    env: dict = None) -> dict:
    """Run a command asynchronously using exec (no shell) for safety."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {
            "returncode": proc.returncode,
            "stdout": stdout.decode(errors="replace").strip(),
            "stderr": stderr.decode(errors="replace").strip(),
        }
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()  # Reap the killed process to prevent zombies
        return {"returncode": -1, "stdout": "", "stderr": "timeout"}
    except Exception as e:
        return {"returncode": -1, "stdout": "", "stderr": str(e)}


async def _run_shell(cmd: str, timeout: int = 30) -> dict:
    """Run a shell command asynchronously. Only use for commands with no
    user-controlled input, or where all user values have been sanitized
    with shlex.quote()."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {
            "returncode": proc.returncode,
            "stdout": stdout.decode(errors="replace").strip(),
            "stderr": stderr.decode(errors="replace").strip(),
        }
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()  # Reap the killed process to prevent zombies
        return {"returncode": -1, "stdout": "", "stderr": "timeout"}
    except Exception as e:
        return {"returncode": -1, "stdout": "", "stderr": str(e)}


class DesktopAutomation:
    """Full desktop automation controller for AI agents."""

    def __init__(self):
        self.pe_compat_prefix = os.environ.get(
            "PE_COMPAT_PREFIX",
            os.path.expanduser("~/.pe-compat")
        )
        self._ensure_dirs()

    def _ensure_dirs(self):
        """Ensure required directories exist."""
        dirs = [
            f"{self.pe_compat_prefix}/drives/c/Games",
            f"{self.pe_compat_prefix}/drives/c/Program Files",
            f"{self.pe_compat_prefix}/logs",
            os.path.expanduser("~/Games"),
            os.path.expanduser("~/Desktop"),
        ]
        for d in dirs:
            os.makedirs(d, exist_ok=True)

    # ==========================================
    # Application Management
    # ==========================================

    async def launch_app(self, command: str, args: list[str] = None,
                         working_dir: str = None) -> dict:
        """Launch a Linux or Windows application."""
        args = args or []

        # Detect if it's a .exe file
        if command.lower().endswith('.exe'):
            full_cmd = ["/usr/bin/pe-run-game", command] + args
        else:
            full_cmd = [command] + args

        try:
            env = os.environ.copy()
            if not env.get("DISPLAY"):
                env["DISPLAY"] = ":0"

            proc = subprocess.Popen(
                full_cmd,
                cwd=working_dir,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return {"success": True, "pid": proc.pid, "command": " ".join(full_cmd)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def launch_exe(self, exe_path: str, args: list[str] = None,
                         diag: bool = False) -> dict:
        """Launch a Windows .exe file via PE Loader."""
        args = args or []
        cmd = ["/usr/bin/pe-run-game"]
        if diag:
            cmd.append("--diag")
        cmd.append(exe_path)
        cmd.extend(args)

        try:
            env = os.environ.copy()
            if not env.get("DISPLAY"):
                env["DISPLAY"] = ":0"

            proc = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(exe_path) if os.path.isabs(exe_path) else None,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return {"success": True, "pid": proc.pid, "exe": exe_path}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def list_running_apps(self) -> list[dict]:
        """List running graphical applications.

        wmctrl -l -p columns: window_id  desktop  pid  host  title
        """
        r = await _run_shell("wmctrl -l -p 2>/dev/null || xdotool search --name '' 2>/dev/null")
        apps = []
        if r["returncode"] == 0:
            for line in r["stdout"].split("\n"):
                if not line.strip():
                    continue
                parts = line.split(None, 4)
                if len(parts) >= 5:
                    apps.append({
                        "window_id": parts[0],
                        "desktop": parts[1],
                        "pid": parts[2],
                        "host": parts[3],
                        "title": parts[4],
                    })
                elif len(parts) == 4:
                    # Title is empty
                    apps.append({
                        "window_id": parts[0],
                        "desktop": parts[1],
                        "pid": parts[2],
                        "host": parts[3],
                        "title": "",
                    })
        return apps

    async def close_app(self, window_id: str = None, pid: int = None) -> dict:
        """Close an application by window ID or PID."""
        if window_id:
            r = await _run_exec(["xdotool", "windowclose", str(window_id)])
            return {"success": r["returncode"] == 0}
        elif pid:
            try:
                os.kill(pid, 15)  # SIGTERM
                return {"success": True}
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {"success": False, "error": "No window_id or pid specified"}

    # ==========================================
    # Window Management
    # ==========================================

    async def get_active_window(self) -> dict:
        """Get information about the currently active window."""
        r = await _run_exec(["xdotool", "getactivewindow", "getwindowname"])
        wid = await _run_exec(["xdotool", "getactivewindow"])
        return {
            "window_id": wid["stdout"],
            "title": r["stdout"],
        }

    async def focus_window(self, window_id: str) -> dict:
        """Focus a window by ID."""
        r = await _run_exec(["xdotool", "windowfocus", "--sync", str(window_id)])
        return {"success": r["returncode"] == 0}

    async def move_window(self, window_id: str, x: int, y: int) -> dict:
        """Move a window to a specific position."""
        r = await _run_exec(["xdotool", "windowmove", str(window_id), str(x), str(y)])
        return {"success": r["returncode"] == 0}

    async def resize_window(self, window_id: str, width: int, height: int) -> dict:
        """Resize a window."""
        r = await _run_exec(["xdotool", "windowsize", str(window_id), str(width), str(height)])
        return {"success": r["returncode"] == 0}

    async def minimize_window(self, window_id: str) -> dict:
        """Minimize a window."""
        r = await _run_exec(["xdotool", "windowminimize", str(window_id)])
        return {"success": r["returncode"] == 0}

    async def maximize_window(self, window_id: str) -> dict:
        """Maximize a window using wmctrl."""
        safe_wid = shlex.quote(str(window_id))
        r = await _run_shell(
            f"wmctrl -i -r {safe_wid} -b add,maximized_vert,maximized_horz 2>/dev/null || "
            f"xdotool key --window {safe_wid} super+Up"
        )
        return {"success": r["returncode"] == 0}

    # ==========================================
    # Game Management
    # ==========================================

    async def scan_games(self) -> list[dict]:
        """Scan for installed Windows games (.exe files)."""
        search_dirs = [
            f"{self.pe_compat_prefix}/drives/c/Games",
            f"{self.pe_compat_prefix}/drives/c/Program Files",
            os.path.expanduser("~/Games"),
        ]
        games = []
        seen = set()

        for search_dir in search_dirs:
            if not os.path.isdir(search_dir):
                continue
            for root, dirs, files in os.walk(search_dir):
                for f in files:
                    if f.lower().endswith('.exe'):
                        full_path = os.path.join(root, f)
                        # Skip common non-game executables
                        lower = f.lower()
                        if any(skip in lower for skip in [
                            'unins', 'setup', 'install', 'update', 'crash',
                            'redist', 'vcredist', 'dxsetup', 'dotnet',
                        ]):
                            continue
                        if full_path not in seen:
                            seen.add(full_path)
                            size = os.path.getsize(full_path)
                            games.append({
                                "name": os.path.splitext(f)[0],
                                "filename": f,
                                "path": full_path,
                                "directory": root,
                                "size_mb": round(size / (1024 * 1024), 1),
                            })

        return sorted(games, key=lambda g: g["name"].lower())

    async def launch_game(self, exe_path: str, args: list[str] = None) -> dict:
        """Launch a game with optimal settings."""
        return await self.launch_exe(exe_path, args)

    async def create_game_shortcut(self, exe_path: str, name: str = None,
                                    icon: str = None) -> dict:
        """Create a desktop shortcut for a game."""
        if not name:
            name = os.path.splitext(os.path.basename(exe_path))[0]
        icon = icon or "applications-games"

        desktop_dir = os.path.expanduser("~/Desktop")
        os.makedirs(desktop_dir, exist_ok=True)

        # Sanitize fields to prevent .desktop file injection (newlines, semicolons in Name/Exec)
        safe_name = name.replace('\n', ' ').replace('\r', ' ').replace(';', '_')
        safe_filename = safe_name.replace('/', '_').replace('\x00', '')
        desktop_file = os.path.join(desktop_dir, f"{safe_filename}.desktop")
        safe_exe = exe_path.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '').replace('\r', '')
        safe_icon = (icon or "applications-games").replace('\n', '').replace('\r', '')
        content = f"""[Desktop Entry]
Type=Application
Name={safe_name}
Comment=Windows Game - {safe_name}
Exec=/usr/bin/pe-run-game "{safe_exe}"
Icon={safe_icon}
Terminal=false
Categories=Game;
StartupNotify=true
"""
        with open(desktop_file, 'w') as f:
            f.write(content)
        os.chmod(desktop_file, 0o755)

        # Trust the shortcut for XFCE
        await _run_exec(["gio", "set", desktop_file, "metadata::trusted", "true"])

        return {"success": True, "shortcut": desktop_file, "name": name}

    async def get_game_info(self, exe_path: str) -> dict:
        """Get diagnostic info about a game executable."""
        r = await _run_exec(["/usr/bin/peloader", "--diag", exe_path], timeout=10)
        return {
            "path": exe_path,
            "name": os.path.basename(exe_path),
            "size_mb": round(os.path.getsize(exe_path) / (1024 * 1024), 1) if os.path.exists(exe_path) else 0,
            "diagnostics": r["stdout"],
        }

    # ==========================================
    # Desktop Shortcut Management
    # ==========================================

    async def list_shortcuts(self) -> list[dict]:
        """List all desktop shortcuts."""
        desktop_dir = os.path.expanduser("~/Desktop")
        shortcuts = []
        if os.path.isdir(desktop_dir):
            for f in os.listdir(desktop_dir):
                if f.endswith('.desktop'):
                    path = os.path.join(desktop_dir, f)
                    info = self._parse_desktop_file(path)
                    if info:
                        shortcuts.append(info)
        return shortcuts

    async def create_shortcut(self, name: str, command: str,
                               icon: str = "application-x-executable",
                               comment: str = "") -> dict:
        """Create a generic desktop shortcut."""
        desktop_dir = os.path.expanduser("~/Desktop")
        os.makedirs(desktop_dir, exist_ok=True)

        # Sanitize to prevent .desktop file injection via newlines/semicolons
        safe_name = name.replace('\n', ' ').replace('\r', ' ').replace(';', '_')
        safe_command = shlex.quote(command.replace('\n', '').replace('\r', ''))
        safe_icon = icon.replace('\n', '').replace('\r', '')
        safe_comment = comment.replace('\n', ' ').replace('\r', ' ')

        # Remove path separators / null bytes from filename to prevent path traversal
        safe_filename = safe_name.replace('/', '_').replace('\x00', '')
        desktop_file = os.path.join(desktop_dir, f"{safe_filename}.desktop")

        content = f"""[Desktop Entry]
Type=Application
Name={safe_name}
Comment={safe_comment}
Exec={safe_command}
Icon={safe_icon}
Terminal=false
StartupNotify=true
"""
        with open(desktop_file, 'w') as f:
            f.write(content)
        os.chmod(desktop_file, 0o755)
        await _run_exec(["gio", "set", desktop_file, "metadata::trusted", "true"])

        return {"success": True, "shortcut": desktop_file}

    async def delete_shortcut(self, name: str) -> dict:
        """Delete a desktop shortcut."""
        safe_name = os.path.basename(name)
        if not safe_name or '..' in safe_name:
            return {"success": False, "error": "Invalid name"}
        desktop_dir = os.path.expanduser("~/Desktop")
        desktop_file = os.path.join(desktop_dir, f"{safe_name}.desktop")
        if os.path.exists(desktop_file):
            os.remove(desktop_file)
            return {"success": True}
        return {"success": False, "error": "Shortcut not found"}

    def _parse_desktop_file(self, path: str) -> Optional[dict]:
        """Parse a .desktop file and return its info."""
        try:
            info = {"path": path, "filename": os.path.basename(path)}
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line:
                        key, _, val = line.partition('=')
                        if key == "Name":
                            info["name"] = val
                        elif key == "Exec":
                            info["exec"] = val
                        elif key == "Icon":
                            info["icon"] = val
                        elif key == "Comment":
                            info["comment"] = val
            return info if "name" in info else None
        except Exception:
            return None

    # ==========================================
    # Notifications
    # ==========================================

    async def send_notification(self, title: str, message: str,
                                 icon: str = "dialog-information",
                                 urgency: str = "normal") -> dict:
        """Send a desktop notification."""
        env = os.environ.copy()
        env["DISPLAY"] = ":0"
        r = await _run_exec(
            ["notify-send", "-u", str(urgency), "-i", str(icon),
             str(title), str(message)],
            env=env,
        )
        return {"success": r["returncode"] == 0}

    # ==========================================
    # Clipboard
    # ==========================================

    async def get_clipboard(self) -> dict:
        """Get clipboard content."""
        env = os.environ.copy()
        env["DISPLAY"] = ":0"
        r = await _run_exec(
            ["xclip", "-selection", "clipboard", "-o"],
            env=env,
        )
        return {"content": r["stdout"]}

    async def set_clipboard(self, text: str) -> dict:
        """Set clipboard content."""
        env = os.environ.copy()
        env["DISPLAY"] = ":0"
        try:
            proc = await asyncio.create_subprocess_exec(
                "xclip", "-selection", "clipboard",
                stdin=asyncio.subprocess.PIPE,
                env=env,
            )
            await asyncio.wait_for(proc.communicate(text.encode()), timeout=10)
            return {"success": proc.returncode == 0}
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"success": False, "error": "xclip timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ==========================================
    # Scheduled Tasks
    # ==========================================

    async def list_scheduled_tasks(self) -> list[dict]:
        """List cron jobs (scheduled tasks)."""
        r = await _run_exec(["crontab", "-l"])
        tasks = []
        if r["returncode"] == 0:
            for i, line in enumerate(r["stdout"].split("\n")):
                line = line.strip()
                if line and not line.startswith("#"):
                    tasks.append({"id": i, "schedule": line})
        return tasks

    async def add_scheduled_task(self, schedule: str, command: str) -> dict:
        """Add a cron job. Schedule format: '0 * * * *' (cron format)."""
        import re
        # Validate cron schedule format (5 fields: min hour dom month dow)
        # Each field: number, *, */N, N-N, or comma-separated list
        cron_field = r'(\*(/\d+)?|\d+(-\d+)?)(,(\*(/\d+)?|\d+(-\d+)?))*'
        cron_re = re.compile(
            rf'^{cron_field}\s+{cron_field}\s+{cron_field}\s+{cron_field}\s+{cron_field}$'
        )
        schedule = schedule.strip()
        if not cron_re.match(schedule):
            return {"success": False, "error": "Invalid cron schedule format. Expected: 'min hour dom month dow'"}
        # The cron entry is written to a temp file and loaded via `crontab <file>`,
        # bypassing shell interpolation. Cron itself runs the command via sh -c,
        # so we use the raw command string (not shell-quoted).
        entry = f"{schedule} {command}"
        import tempfile
        try:
            # Get existing crontab
            existing = await _run_exec(["crontab", "-l"])
            lines = existing["stdout"] if existing["returncode"] == 0 else ""
            new_crontab = lines + "\n" + entry + "\n" if lines else entry + "\n"
            with tempfile.NamedTemporaryFile(mode='w', suffix='.cron', delete=False) as tmp:
                tmp.write(new_crontab)
                tmp_path = tmp.name
            r = await _run_exec(["crontab", tmp_path])
            os.unlink(tmp_path)
            return {"success": r["returncode"] == 0}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ==========================================
    # System Theme / Appearance
    # ==========================================

    async def set_wallpaper(self, path: str) -> dict:
        """Set desktop wallpaper."""
        if not os.path.exists(path):
            return {"success": False, "error": "File not found"}
        env = os.environ.copy()
        env["DISPLAY"] = ":0"
        r = await _run_exec(
            ["xfconf-query", "-c", "xfce4-desktop",
             "-p", "/backdrop/screen0/monitorVirtual-1/workspace0/last-image",
             "-s", path],
            env=env,
        )
        return {"success": r["returncode"] == 0}

    async def get_screen_resolution(self) -> dict:
        """Get current screen resolution."""
        r = await _run_shell("DISPLAY=:0 xrandr --current 2>/dev/null | grep '*'")
        if r["stdout"]:
            parts = r["stdout"].strip().split()
            if parts:
                res = parts[0]
                try:
                    w, h = res.split("x", 1)
                    return {"width": int(w), "height": int(h), "resolution": res}
                except (ValueError, TypeError):
                    logger.warning("Could not parse resolution from xrandr: %s", res)
        return {"width": 0, "height": 0, "resolution": "unknown"}

    async def set_screen_resolution(self, width: int, height: int) -> dict:
        """Set screen resolution."""
        # Auto-detect active output
        env = os.environ.copy()
        env["DISPLAY"] = ":0"
        detect = await _run_exec(["xrandr", "--current"], env=env)
        output_name = "Virtual-1"  # fallback
        if detect["returncode"] == 0:
            for line in detect["stdout"].split("\n"):
                if " connected" in line:
                    output_name = line.split()[0]
                    break
        r = await _run_exec(
            ["xrandr", "--output", output_name, "--mode",
             f"{int(width)}x{int(height)}"],
            env=env,
        )
        return {"success": r["returncode"] == 0}
