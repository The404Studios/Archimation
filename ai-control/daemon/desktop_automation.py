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
import re
import shlex
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ai-control.desktop")


def _reap_after_spawn(proc: subprocess.Popen) -> None:
    """Defense-in-depth: wait on a fire-and-forget child in a daemon thread.

    Session 24: even with SIGCHLD=SIG_IGN installed in main.py, a daemon
    thread calling proc.wait() guarantees the Python-side Popen object's
    returncode is set and no /proc/<pid> zombie lingers if a future Python
    runtime or child watcher reclaims SIGCHLD semantics.

    The thread is marked daemon=True so it never blocks interpreter exit.
    Errors are swallowed — the child was already launched, so the caller's
    success signal (PID returned) must not be falsified by a reaper error.
    """
    def _waiter():
        try:
            proc.wait()
        except Exception:
            pass
    t = threading.Thread(target=_waiter, name=f"pe-reaper-{proc.pid}", daemon=True)
    t.start()

# Pre-compiled cron schedule regex (was compiled on every add_scheduled_task).
_CRON_FIELD = r'(\*(/\d+)?|\d+(-\d+)?)(,(\*(/\d+)?|\d+(-\d+)?))*'
_CRON_RE = re.compile(
    rf'^{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}\s+{_CRON_FIELD}$'
)


def _display_env() -> dict:
    """Return an env dict with DISPLAY set, reusing a cached copy when possible.

    os.environ.copy() builds a full dict every call; on hot paths (clipboard,
    notifications, wallpaper, etc.) this is pure overhead when DISPLAY is
    already correct.
    """
    env = os.environ.copy()
    if not env.get("DISPLAY"):
        env["DISPLAY"] = ":0"
    return env


async def _run_exec(argv: list[str], timeout: int = 30,
                    env: dict = None) -> dict:
    """Run a command asynchronously using exec (no shell) for safety."""
    proc = None
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
        if proc is not None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()  # Reap the killed process to prevent zombies
            except Exception:
                pass
        return {"returncode": -1, "stdout": "", "stderr": "timeout"}
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
        return {"returncode": -1, "stdout": "", "stderr": str(e)}


async def _run_shell(cmd: str, timeout: int = 30) -> dict:
    """Run a shell command asynchronously. Only use for commands with no
    user-controlled input, or where all user values have been sanitized
    with shlex.quote()."""
    proc = None
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
        if proc is not None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()  # Reap the killed process to prevent zombies
            except Exception:
                pass
        return {"returncode": -1, "stdout": "", "stderr": "timeout"}
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
        return {"returncode": -1, "stdout": "", "stderr": str(e)}


class DesktopAutomation:
    """Full desktop automation controller for AI agents."""

    def __init__(self):
        self.pe_compat_prefix = os.environ.get(
            "PE_COMPAT_PREFIX",
            os.path.expanduser("~/.pe-compat")
        )
        self._ensure_dirs()
        # Cached resolution — avoids shell-piped `xrandr | grep` every call.
        self._res_cache: Optional[tuple[dict, float]] = None
        # Cached games scan: walking drives/c/Games + Program Files + ~/Games
        # can be hundreds of stat()s on a slow HDD. The set of installed games
        # rarely changes between requests, so a 60s TTL is invisible to the UI
        # and saves a huge amount of work when /games is polled (which the
        # desktop panel does every few seconds on some sessions).
        self._games_cache: Optional[tuple[list, float]] = None
        self._GAMES_TTL = 60.0
        # Cached clipboard env (avoids os.environ.copy() on every call; DISPLAY
        # is set once at daemon startup and doesn't change mid-session).
        self._display_env_cache: Optional[dict] = None

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
            env = self._get_display_env()

            proc = subprocess.Popen(
                full_cmd,
                cwd=working_dir,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            # Session 24: spawn a daemon reaper thread so the Popen object's
            # returncode gets set once the child exits. SIGCHLD=SIG_IGN in
            # main.py already asks the kernel to auto-reap, but this keeps the
            # Python-side state consistent and adds a fallback path.
            _reap_after_spawn(proc)
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
            env = self._get_display_env()

            proc = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(exe_path) if os.path.isabs(exe_path) else None,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            # Session 24: see launch_app — daemon reaper thread ensures Python
            # Popen state is cleaned up and the child is never left as <defunct>.
            _reap_after_spawn(proc)
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
        """Get information about the currently active window.

        Single xdotool invocation chains getactivewindow → getwindowname →
        getactivewindow, returning both on consecutive lines. Previously we
        forked xdotool twice, doubling the subprocess cost per call (hot
        path for Contusion window tracking on slow hardware).
        """
        r = await _run_exec(
            ["xdotool", "getactivewindow", "getwindowname",
             "getactivewindow"]
        )
        lines = r["stdout"].split("\n") if r["stdout"] else []
        title = lines[0] if lines else ""
        # getactivewindow on a chained call emits the numeric id last
        wid = lines[-1] if len(lines) >= 2 else ""
        return {
            "window_id": wid,
            "title": title,
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

    _SKIP_EXE_TOKENS = ("unins", "setup", "install", "update", "crash",
                        "redist", "vcredist", "dxsetup", "dotnet")

    def _scan_games_sync(self) -> list[dict]:
        """Blocking directory walk. Called from executor by scan_games()."""
        search_dirs = [
            f"{self.pe_compat_prefix}/drives/c/Games",
            f"{self.pe_compat_prefix}/drives/c/Program Files",
            os.path.expanduser("~/Games"),
        ]
        games = []
        seen = set()
        skip_tokens = self._SKIP_EXE_TOKENS

        for search_dir in search_dirs:
            if not os.path.isdir(search_dir):
                continue
            for root, dirs, files in os.walk(search_dir):
                for f in files:
                    if not f.lower().endswith('.exe'):
                        continue
                    lower = f.lower()
                    if any(tok in lower for tok in skip_tokens):
                        continue
                    full_path = os.path.join(root, f)
                    if full_path in seen:
                        continue
                    seen.add(full_path)
                    try:
                        size = os.path.getsize(full_path)
                    except OSError:
                        continue
                    games.append({
                        "name": os.path.splitext(f)[0],
                        "filename": f,
                        "path": full_path,
                        "directory": root,
                        "size_mb": round(size / (1024 * 1024), 1),
                    })
        games.sort(key=lambda g: g["name"].lower())
        return games

    async def scan_games(self) -> list[dict]:
        """Scan for installed Windows games (.exe files).

        Result is cached for ``_GAMES_TTL`` seconds — the directory walk
        can be hundreds of stat() calls on a slow HDD. Two panel widgets
        polling /games every few seconds would otherwise hammer the disk.
        """
        now = time.monotonic()
        cached = self._games_cache
        if cached is not None and (now - cached[1]) < self._GAMES_TTL:
            return cached[0]
        # Offload the blocking walk to an executor so the event loop keeps
        # serving other endpoints while we stat() dozens of .exe files.
        loop = asyncio.get_running_loop()
        games = await loop.run_in_executor(None, self._scan_games_sync)
        self._games_cache = (games, now)
        return games

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

    def _get_display_env(self) -> dict:
        """Return a (cached) env dict with DISPLAY set. os.environ.copy()
        copies 50-100 entries on every call for no benefit when DISPLAY is
        already correct for the daemon's lifetime."""
        env = self._display_env_cache
        if env is not None:
            return env
        env = os.environ.copy()
        if not env.get("DISPLAY"):
            env["DISPLAY"] = ":0"
        self._display_env_cache = env
        return env

    async def send_notification(self, title: str, message: str,
                                 icon: str = "dialog-information",
                                 urgency: str = "normal") -> dict:
        """Send a desktop notification."""
        r = await _run_exec(
            ["notify-send", "-u", str(urgency), "-i", str(icon),
             str(title), str(message)],
            env=self._get_display_env(),
        )
        return {"success": r["returncode"] == 0}

    # ==========================================
    # Clipboard
    # ==========================================

    async def get_clipboard(self) -> dict:
        """Get clipboard content."""
        r = await _run_exec(
            ["xclip", "-selection", "clipboard", "-o"],
            env=self._get_display_env(),
        )
        return {"content": r["stdout"]}

    async def set_clipboard(self, text: str) -> dict:
        """Set clipboard content."""
        env = self._get_display_env()
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "xclip", "-selection", "clipboard",
                stdin=asyncio.subprocess.PIPE,
                env=env,
            )
            await asyncio.wait_for(proc.communicate(text.encode()), timeout=10)
            return {"success": proc.returncode == 0}
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
            return {"success": False, "error": "xclip timed out"}
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
        # Validate cron schedule format (5 fields: min hour dom month dow)
        # Each field: number, *, */N, N-N, or comma-separated list
        schedule = schedule.strip()
        if not _CRON_RE.match(schedule):
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
        r = await _run_exec(
            ["xfconf-query", "-c", "xfce4-desktop",
             "-p", "/backdrop/screen0/monitorVirtual-1/workspace0/last-image",
             "-s", path],
            env=self._get_display_env(),
        )
        return {"success": r["returncode"] == 0}

    async def get_screen_resolution(self) -> dict:
        """Get current screen resolution."""
        # Cache briefly — spawning xrandr + grep shell pipeline is costly on
        # slow hardware and resolution rarely changes mid-session.
        now = time.monotonic()
        if self._res_cache is not None and (now - self._res_cache[1]) < 15.0:
            return self._res_cache[0]
        r = await _run_shell("DISPLAY=:0 xrandr --current 2>/dev/null | grep '*'")
        result = {"width": 0, "height": 0, "resolution": "unknown"}
        if r["stdout"]:
            parts = r["stdout"].strip().split()
            if parts:
                res = parts[0]
                try:
                    w, h = res.split("x", 1)
                    result = {"width": int(w), "height": int(h), "resolution": res}
                except (ValueError, TypeError):
                    logger.warning("Could not parse resolution from xrandr: %s", res)
        self._res_cache = (result, now)
        return result

    async def set_screen_resolution(self, width: int, height: int) -> dict:
        """Set screen resolution."""
        # Auto-detect active output
        env = self._get_display_env()
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
