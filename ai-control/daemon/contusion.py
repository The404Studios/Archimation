"""
Contusion -- Automation pipeline engine for AI-controlled desktop.

Process control, GUI automation (xdotool/xclip/scrot), macro recording,
application library, natural-language context router, and chainable pipelines.
"""

import asyncio, json, logging, os, re, shlex, signal, time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ai-control.contusion")
MACRO_DIR = Path.home() / ".contusion" / "macros"

# Pre-compiled regexes used by _route_fallback -- moved to module level so
# repeated route() calls don't re-compile on each invocation.
_RE_SCREENSHOT = re.compile(r"\bscreenshot\b")
_RE_INSTALL = re.compile(r"\binstall\s+([\w.-]+)")
_RE_OPEN_APP = re.compile(r"\b(?:open|launch|start|run)\s+([\w.-]+)")
_RE_GO_TO_URL = re.compile(r"\bgo\s+to\s+(https?://\S+|[\w.-]+\.\w+\S*)")
_RE_TYPE_CMD = re.compile(r"\btype\s+[\"']?(.+?)[\"']?\s*$")
_RE_PRESS_CMD = re.compile(r"\bpress\s+([\w+]+)")

# Import the dictionary/context engine for NLP-powered command resolution
try:
    from contusion_dictionary import (
        get_engine as _get_dict_engine, parse_request as _dict_parse,
        search_commands as _dict_search, get_app_profile as _dict_app_profile,
        get_stats as _dict_stats, SecurityLevel, TRUST_THRESHOLDS,
        Action as DictAction,
    )
    _HAS_DICTIONARY = True
except ImportError:
    _HAS_DICTIONARY = False
    logger.warning("contusion_dictionary not available -- NLP routing degraded")

# -- Application library (30+ apps) ----------------------------------------

APP_LIBRARY: dict[str, dict] = {
    "firefox":     {"launch": "firefox", "type": "gui", "shortcuts": {
                        "new_tab": "ctrl+t", "close_tab": "ctrl+w", "address_bar": "ctrl+l",
                        "refresh": "F5", "find": "ctrl+f", "private": "ctrl+shift+p"}},
    "terminal":    {"launch": "xfce4-terminal", "type": "gui", "shortcuts": {
                        "new_tab": "ctrl+shift+t", "paste": "ctrl+shift+v", "copy": "ctrl+shift+c"}},
    "terminator":  {"launch": "terminator", "type": "gui"},
    "thunar":      {"launch": "thunar", "type": "gui", "shortcuts": {"new_window": "ctrl+n", "address_bar": "ctrl+l"}},
    "discord":     {"launch": "discord", "type": "gui"},
    "steam":       {"launch": "steam", "type": "gui"},
    "code":        {"launch": "code", "type": "gui", "shortcuts": {
                        "terminal": "ctrl+grave", "palette": "ctrl+shift+p", "save": "ctrl+s", "find": "ctrl+f"}},
    "vlc":         {"launch": "vlc", "type": "gui", "shortcuts": {"play_pause": "space", "fullscreen": "f"}},
    "gimp":        {"launch": "gimp", "type": "gui"},
    "libreoffice": {"launch": "libreoffice", "type": "gui"},
    "blender":     {"launch": "blender", "type": "gui"},
    "obs":         {"launch": "obs", "type": "gui"},
    "audacity":    {"launch": "audacity", "type": "gui"},
    "inkscape":    {"launch": "inkscape", "type": "gui"},
    "nautilus":    {"launch": "nautilus", "type": "gui"},
    "htop":        {"launch": "htop", "type": "tui"},
    "nvtop":       {"launch": "nvtop", "type": "tui"},
    "pacman":      {"launch": "pacman", "type": "cli", "commands": {
                        "install": "-S --noconfirm", "remove": "-R --noconfirm",
                        "update": "-Syu --noconfirm", "search": "-Ss", "info": "-Qi", "list": "-Q"}},
    "yay":         {"launch": "yay", "type": "cli", "commands": {
                        "install": "-S --noconfirm", "search": "-Ss", "update": "-Syu --noconfirm"}},
    "git":         {"launch": "git", "type": "cli", "commands": {
                        "clone": "clone", "pull": "pull", "push": "push", "status": "status",
                        "log": "log --oneline -20", "commit": "commit", "diff": "diff"}},
    "systemctl":   {"launch": "systemctl", "type": "cli", "commands": {
                        "start": "start", "stop": "stop", "restart": "restart", "status": "status",
                        "enable": "enable", "disable": "disable", "list": "list-units --type=service --no-pager"}},
    "journalctl":  {"launch": "journalctl", "type": "cli", "commands": {"follow": "-f", "boot": "-b", "unit": "-u"}},
    "docker":      {"launch": "docker", "type": "cli", "commands": {
                        "ps": "ps", "run": "run", "build": "build", "images": "images", "stop": "stop"}},
    "curl":        {"launch": "curl", "type": "cli"},
    "wget":        {"launch": "wget", "type": "cli"},
    "rsync":       {"launch": "rsync", "type": "cli"},
    "ssh":         {"launch": "ssh", "type": "cli"},
    "tmux":        {"launch": "tmux", "type": "tui", "commands": {"new": "new-session", "list": "list-sessions", "attach": "attach"}},
    "neofetch":    {"launch": "neofetch", "type": "cli"},
    "ip":          {"launch": "ip", "type": "cli", "commands": {"addr": "addr", "route": "route", "link": "link"}},
    "nmcli":       {"launch": "nmcli", "type": "cli", "commands": {
                        "status": "general status", "wifi": "device wifi list", "connect": "connection up"}},
    # Round 3 additions -- commonly requested apps the user might say:
    # "launch thunderbird", "open chrome", "start file manager".
    "thunderbird": {"launch": "thunderbird", "type": "gui", "shortcuts": {
                        "compose": "ctrl+n", "reply": "ctrl+r", "send": "ctrl+Return"}},
    "chromium":    {"launch": "chromium", "type": "gui", "shortcuts": {
                        "new_tab": "ctrl+t", "close_tab": "ctrl+w", "incognito": "ctrl+shift+n"}},
    "chrome":      {"launch": "sh -c 'google-chrome-stable 2>/dev/null || chromium'",
                    "type": "gui"},
    "google-chrome": {"launch": "sh -c 'google-chrome-stable 2>/dev/null || chromium'",
                      "type": "gui"},
    "files":       {"launch": "thunar", "type": "gui"},
    "file-manager":{"launch": "thunar", "type": "gui"},
    "file_manager":{"launch": "thunar", "type": "gui"},
    "vscode":      {"launch": "code", "type": "gui"},
    "krita":       {"launch": "krita", "type": "gui"},
    "spotify":     {"launch": "spotify", "type": "gui"},
    "telegram":    {"launch": "telegram-desktop", "type": "gui"},
    "signal":      {"launch": "signal-desktop", "type": "gui"},
    "evince":      {"launch": "evince", "type": "gui"},
    "flameshot":   {"launch": "flameshot", "type": "gui"},
    "mpv":         {"launch": "mpv", "type": "gui"},
    "alacritty":   {"launch": "alacritty", "type": "gui"},
    "kitty":       {"launch": "kitty", "type": "gui"},
    "btop":        {"launch": "btop", "type": "tui"},
    "lutris":      {"launch": "lutris", "type": "gui"},
}

# -- Subprocess helpers -----------------------------------------------------

async def _run_exec(argv: list[str], timeout: int = 30,
                    env: dict = None, stdin_data: bytes = None) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else None, env=env)
        stdout, stderr = await asyncio.wait_for(proc.communicate(input=stdin_data), timeout=timeout)
        return {"returncode": proc.returncode,
                "stdout": stdout.decode(errors="replace").strip(),
                "stderr": stderr.decode(errors="replace").strip()}
    except asyncio.TimeoutError:
        proc.kill(); await proc.wait()
        return {"returncode": -1, "stdout": "", "stderr": "timeout"}
    except Exception as e:
        return {"returncode": -1, "stdout": "", "stderr": str(e)}

def _display_env() -> dict:
    env = os.environ.copy(); env.setdefault("DISPLAY", ":0"); return env

# -- Action / Pipeline ------------------------------------------------------

@dataclass
class Action:
    kind: str
    params: dict = field(default_factory=dict)
    def __init__(self, kind: str, **kwargs):
        self.kind = kind; self.params = kwargs

@dataclass
class Pipeline:
    actions: list[Action] = field(default_factory=list)
    name: str = ""

# -- Contusion engine -------------------------------------------------------

class Contusion:
    """Core automation: process control, GUI, macros, app library, router, pipelines."""

    def __init__(self):
        MACRO_DIR.mkdir(parents=True, exist_ok=True)
        self._recording: Optional[str] = None
        self._recorded_actions: list[dict] = []
        # Monotonic timestamp of the last recorded event -- used to
        # compute inter-event delays so macro playback preserves timing.
        self._last_record_time: Optional[float] = None

    # -- 1. Process Control -------------------------------------------------

    async def run_command(self, cmd: str, stdin: str = None, timeout: int = 30) -> dict:
        """Run a shell command, optionally feeding stdin."""
        return await _run_exec(["bash", "-c", cmd], timeout=timeout,
                               stdin_data=stdin.encode() if stdin else None)

    async def run_interactive(self, cmd: str, inputs: list[str] = None, timeout: int = 30) -> dict:
        """Run interactive program, sending inputs one per line."""
        payload = ("\n".join(inputs or []) + "\n").encode()
        return await _run_exec(["bash", "-c", cmd], timeout=timeout, stdin_data=payload)

    async def get_running_processes(self) -> list[dict]:
        r = await _run_exec(["ps", "aux", "--no-headers"], timeout=10)
        procs = []
        for line in r["stdout"].split("\n"):
            parts = line.split(None, 10)
            if len(parts) >= 11:
                try:
                    procs.append({"user": parts[0], "pid": int(parts[1]),
                                  "cpu": float(parts[2]), "mem": float(parts[3]),
                                  "command": parts[10]})
                except (ValueError, IndexError):
                    continue
        return procs

    async def send_signal(self, pid: int, sig: int = signal.SIGTERM) -> dict:
        try:
            os.kill(pid, sig)
            return {"success": True, "pid": pid, "signal": sig}
        except (ProcessLookupError, PermissionError) as e:
            return {"success": False, "error": str(e)}

    async def read_process_output(self, pid: int) -> dict:
        """Read stdout/stderr of a process via /proc (best effort)."""
        fd_dir = Path(f"/proc/{pid}/fd")
        output = {}
        for fd_name, label in [("1", "stdout"), ("2", "stderr")]:
            try:
                real = (fd_dir / fd_name).resolve()
                output[label] = real.read_text(errors="replace")[-4096:] if real.is_file() else ""
            except (OSError, PermissionError):
                output[label] = ""
        return {"pid": pid, **output}

    # -- 2. GUI Automation --------------------------------------------------

    async def click(self, x: int, y: int, button: int = 1) -> dict:
        env = _display_env()
        r = await _run_exec(["xdotool", "mousemove", "--sync", str(x), str(y), "click", str(button)], env=env)
        self._record("click", x=x, y=y, button=button)
        return {"success": r["returncode"] == 0}

    async def type_text(self, text: str, delay_ms: int = 12) -> dict:
        env = _display_env()
        r = await _run_exec(["xdotool", "type", "--clearmodifiers", "--delay", str(delay_ms), text],
                            env=env, timeout=max(30, len(text) // 10))
        # Use the dispatcher key ("type") so recorded macros replay
        # without hitting "Unknown action kind".
        self._record("type", text=text)
        return {"success": r["returncode"] == 0}

    async def press_key(self, key: str) -> dict:
        env = _display_env()
        r = await _run_exec(["xdotool", "key", "--clearmodifiers", key], env=env)
        # Use the dispatcher key ("press") so recorded macros replay.
        self._record("press", key=key)
        return {"success": r["returncode"] == 0}

    async def find_window(self, name: str) -> list[dict]:
        env = _display_env()
        r = await _run_exec(["xdotool", "search", "--name", name], env=env)
        results = []
        for wid in [w for w in r["stdout"].split("\n") if w.strip()]:
            t = await _run_exec(["xdotool", "getwindowname", wid], env=env)
            results.append({"window_id": wid, "title": t["stdout"]})
        return results

    async def focus_window(self, window_id: str) -> dict:
        r = await _run_exec(["xdotool", "windowfocus", "--sync", str(window_id)], env=_display_env())
        return {"success": r["returncode"] == 0}

    async def screenshot(self, region: Optional[dict] = None, path: str = None) -> dict:
        if not path:
            path = os.path.expanduser(f"~/Pictures/screenshot_{int(time.time())}.png")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        env = _display_env()
        if region:
            geo = f"{region['w']}x{region['h']}+{region['x']}+{region['y']}"
            r = await _run_exec(["scrot", "--autoselect", geo, path], env=env)
        else:
            r = await _run_exec(["scrot", path], env=env)
        self._record("screenshot", path=path)
        return {"success": r["returncode"] == 0, "path": path}

    async def get_active_window(self) -> dict:
        env = _display_env()
        wid = await _run_exec(["xdotool", "getactivewindow"], env=env)
        title = await _run_exec(["xdotool", "getactivewindow", "getwindowname"], env=env)
        return {"window_id": wid["stdout"], "title": title["stdout"]}

    async def move_window(self, window_id: str, x: int, y: int,
                           w: int = None, h: int = None) -> dict:
        env = _display_env(); wid = str(window_id)
        r = await _run_exec(["xdotool", "windowmove", wid, str(x), str(y)], env=env)
        if r["returncode"] != 0:
            return {"success": False, "error": r["stderr"]}
        if w is not None and h is not None:
            r = await _run_exec(["xdotool", "windowsize", wid, str(w), str(h)], env=env)
        return {"success": r["returncode"] == 0}

    # -- 3. Macro System ----------------------------------------------------

    def record_macro(self, name: str) -> dict:
        self._recording = name
        self._recorded_actions = []
        self._last_record_time = time.monotonic()
        logger.info("Macro recording started: %s", name)
        return {"recording": True, "name": name}

    def stop_recording(self) -> dict:
        if not self._recording:
            return {"success": False, "error": "Not recording"}
        macro_path = MACRO_DIR / f"{self._recording}.json"
        macro_path.write_text(json.dumps(self._recorded_actions, indent=2))
        count, name = len(self._recorded_actions), self._recording
        self._recording = None
        self._recorded_actions = []
        self._last_record_time = None
        logger.info("Macro saved: %s (%d actions)", name, count)
        return {"success": True, "name": name, "actions": count, "path": str(macro_path)}

    async def play_macro(self, name: str, speed: float = 1.0,
                          max_delay: float = 10.0) -> dict:
        """Replay a recorded macro, honoring inter-event timing.

        `speed` > 1 plays faster, < 1 slower. `max_delay` caps any single
        inter-event sleep so a recording with a long pause doesn't hang
        playback indefinitely.
        """
        macro_path = MACRO_DIR / f"{name}.json"
        if not macro_path.exists():
            return {"success": False, "error": f"Macro not found: {name}"}
        actions = json.loads(macro_path.read_text())
        if not isinstance(actions, list):
            return {"success": False, "error": "Malformed macro file"}
        results = []
        for act in actions:
            if not isinstance(act, dict):
                continue
            # Honor recorded inter-event delay (seconds since previous
            # event). Cap at max_delay to avoid runaway waits.
            delay = float(act.get("_delay", 0) or 0) / max(speed, 0.01)
            if delay > 0:
                await asyncio.sleep(min(delay, max_delay))
            kind = act.get("_kind", "unknown")
            action_params = {
                k: v for k, v in act.items()
                if not k.startswith("_")
            }
            results.append({"kind": kind, **(await self._dispatch_action(kind, action_params))})
        return {"success": True, "name": name, "steps": len(results), "results": results}

    def list_macros(self) -> list[dict]:
        macros = []
        for f in sorted(MACRO_DIR.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                macros.append({"name": f.stem, "actions": len(data), "path": str(f)})
            except (json.JSONDecodeError, OSError):
                macros.append({"name": f.stem, "actions": -1, "path": str(f)})
        return macros

    def _record(self, kind: str, **kwargs):
        if self._recording:
            now = time.monotonic()
            delay = 0.0
            if self._last_record_time is not None:
                delay = max(0.0, now - self._last_record_time)
            self._last_record_time = now
            self._recorded_actions.append({
                "_kind": kind,
                "_delay": round(delay, 3),
                **kwargs,
            })

    # -- 4. Application Library ---------------------------------------------

    def get_app_library(self) -> dict:
        return APP_LIBRARY

    def get_app(self, name: str) -> Optional[dict]:
        if not name:
            return None
        key = name.lower().strip()
        # Direct hit
        if key in APP_LIBRARY:
            return APP_LIBRARY[key]
        # Normalize spaces/punctuation to underscore and dash variants
        for variant in (key.replace(" ", "-"), key.replace(" ", "_"),
                        key.replace("-", "_"), key.replace("_", "-")):
            if variant in APP_LIBRARY:
                return APP_LIBRARY[variant]
        # Fall through to dictionary profile if available -- that module
        # has a richer alias table (APP_ALIASES, display-name matching).
        if _HAS_DICTIONARY:
            profile = _dict_app_profile(name)
            if profile:
                return {
                    "launch": profile.launch_cmd.split()[0] if profile.launch_cmd else "",
                    "type": profile.app_type,
                }
        return None

    async def launch_app(self, name: str, args: list[str] = None) -> dict:
        app = self.get_app(name)
        if not app:
            return {"success": False, "error": f"Unknown app: {name}"}
        import subprocess
        try:
            proc = subprocess.Popen([app["launch"]] + (args or []), env=_display_env(),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    start_new_session=True)
            self._record("launch", app=name)
            return {"success": True, "pid": proc.pid, "app": name}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def app_shortcut(self, name: str, shortcut: str) -> dict:
        app = self.get_app(name)
        if not app:
            return {"success": False, "error": f"Unknown app: {name}"}
        key = app.get("shortcuts", {}).get(shortcut)
        if not key:
            return {"success": False, "error": f"Unknown shortcut '{shortcut}' for {name}",
                    "available": list(app.get("shortcuts", {}).keys())}
        return await self.press_key(key)

    # -- 5. Context Router (dictionary-powered) -------------------------------

    # Blocked commands that are never executed regardless of trust level
    _BLOCKED_COMMANDS = frozenset([
        "rm -rf /", "rm -rf /*", "mkfs", "dd if=/dev/zero",
        ":(){ :|:& };:", "> /dev/sda", "chmod -R 777 /",
        "mv / /dev/null",
    ])

    async def route(self, instruction: str, caller_trust: int = 400) -> dict:
        """Parse natural-language instruction via dictionary engine and execute.

        Uses the ContextEngine from contusion_dictionary for NLP parsing,
        security classification, and trust enforcement. Falls back to basic
        regex matching if the dictionary module is unavailable.

        Args:
            instruction: Natural language request (e.g. "open firefox and go to github")
            caller_trust: Trust level of the caller (from auth system). Actions
                          requiring higher trust than the caller has are blocked.
        """
        if _HAS_DICTIONARY:
            return await self._route_dictionary(instruction, caller_trust)
        return await self._route_fallback(instruction)

    async def _route_dictionary(self, instruction: str, caller_trust: int) -> dict:
        """Route via the dictionary's ContextEngine -- full NLP + security."""
        actions = _dict_parse(instruction)
        results: list[dict] = []
        blocked: list[dict] = []

        for act in actions:
            # Security gate: check trust level
            if act.trust > caller_trust:
                blocked.append({
                    "action": act.type, "value": act.value,
                    "description": act.description,
                    "required_trust": act.trust,
                    "caller_trust": caller_trust,
                    "reason": f"Requires trust {act.trust}, caller has {caller_trust}",
                })
                continue

            # Block known-dangerous patterns
            if any(b in act.value for b in self._BLOCKED_COMMANDS):
                blocked.append({
                    "action": act.type, "value": act.value,
                    "reason": "Command is in the blocked list",
                })
                continue

            # Confirmation required for dangerous actions
            if act.confirm:
                results.append({
                    "action": act.type, "value": act.value,
                    "description": act.description,
                    "security": act.security,
                    "needs_confirmation": True,
                    "executed": False,
                })
                continue

            # Execute the action
            r = await self._execute_dict_action(act)
            results.append({
                "action": act.type,
                "value": act.value,
                "description": act.description,
                "security": act.security,
                "executed": True,
                **r,
            })

        executed_results = [r for r in results if r.get("executed", True)]
        success = len(executed_results) > 0 and all(
            r.get("success", True) for r in executed_results
        )
        resp: dict = {"success": success, "results": results}
        if blocked:
            resp["blocked"] = blocked
        return resp

    async def _execute_dict_action(self, act) -> dict:
        """Bridge a dictionary Action into a Contusion execution call."""
        if act.type == "run":
            return await self.run_command(act.value, timeout=120)
        elif act.type == "launch":
            # If the launch value contains shell metacharacters (pipes,
            # redirects, subshells, &&, ||) we must run it via bash
            # rather than splitting on whitespace. Important for
            # fallback launchers like "sh -c 'google-chrome || chromium'".
            if act.value and re.search(r'[|&;<>`$()\\]', act.value):
                return await self.run_command(act.value, timeout=30)
            # Try app library first, fall back to raw command
            app_name = act.value.split()[0] if act.value else ""
            app = self.get_app(app_name)
            if app:
                return await self.launch_app(app_name, act.value.split()[1:] or None)
            return await self.run_command(act.value, timeout=30)
        elif act.type == "type":
            return await self.type_text(act.value)
        elif act.type == "press":
            return await self.press_key(act.value)
        elif act.type == "click":
            parts = act.value.split(",")
            if len(parts) >= 2:
                return await self.click(int(parts[0]), int(parts[1]))
            return {"success": False, "error": "Invalid click coordinates"}
        elif act.type == "wait":
            secs = float(act.value) if act.value else 1.0
            await asyncio.sleep(secs)
            return {"success": True}
        elif act.type == "screenshot":
            return await self.screenshot()
        elif act.type == "search":
            # Return search results from the dictionary itself
            matches = _dict_search(act.value)
            return {"success": True, "matches": matches[:10]}
        else:
            return {"success": False, "error": f"Unknown action type: {act.type}"}

    async def _route_fallback(self, instruction: str) -> dict:
        """Basic regex fallback when dictionary is unavailable."""
        text = instruction.lower().strip()
        results: list[dict] = []

        if _RE_SCREENSHOT.search(text):
            r = await self.screenshot()
            return {"success": True, "results": [{"action": "screenshot", **r}]}

        m = _RE_INSTALL.search(text)
        if m:
            pkg = m.group(1)
            r = await self.run_command(f"pacman -S --noconfirm {shlex.quote(pkg)}", timeout=300)
            results.append({"action": "install", "package": pkg, "success": r["returncode"] == 0})
            if "launch" in text or "open" in text:
                results.append({"action": "launch", **(await self.launch_app(pkg))})
            return {"success": True, "results": results}

        m = _RE_OPEN_APP.search(text)
        if m:
            app_name = m.group(1)
            results.append({"action": "launch", **(await self.launch_app(app_name))})
            url_m = _RE_GO_TO_URL.search(text)
            if url_m:
                url = url_m.group(1)
                if not url.startswith("http"):
                    url = "https://" + url
                await asyncio.sleep(2)
                await self.press_key("ctrl+l")
                await asyncio.sleep(0.3)
                await self.type_text(url)
                await self.press_key("Return")
                results.append({"action": "navigate", "url": url})
            return {"success": True, "results": results}

        m = _RE_TYPE_CMD.search(text)
        if m:
            return {"success": True, "results": [{"action": "type", **(await self.type_text(m.group(1)))}]}
        m = _RE_PRESS_CMD.search(text)
        if m:
            return {"success": True, "results": [{"action": "press", **(await self.press_key(m.group(1)))}]}

        return {"success": False, "error": "Could not understand instruction", "instruction": instruction}

    # -- 5b. Dictionary query helpers ----------------------------------------

    def search_commands(self, query: str) -> list[dict]:
        """Search the command dictionary by keyword."""
        if _HAS_DICTIONARY:
            return _dict_search(query)
        return []

    def get_dictionary_stats(self) -> dict:
        """Return dictionary statistics (command counts, categories, etc.)."""
        if _HAS_DICTIONARY:
            return _dict_stats()
        return {"available": False}

    def get_app_profile(self, name: str) -> dict:
        """Get detailed app profile from the dictionary."""
        if _HAS_DICTIONARY:
            profile = _dict_app_profile(name)
            if profile:
                return {
                    "name": profile.name, "package": profile.package,
                    "launch_cmd": profile.launch_cmd, "type": profile.app_type,
                    "description": profile.description,
                    "shortcuts": profile.shortcuts,
                    "operations": profile.operations,
                    "categories": profile.categories,
                }
        # Fall back to the simple app library
        app = APP_LIBRARY.get(name.lower())
        if app:
            return {"name": name, **app}
        return None

    async def confirm_and_execute(self, action_value: str,
                                   caller_trust: int = 600) -> dict:
        """Execute a previously-blocked dangerous action after confirmation.

        This is called when the user explicitly confirms a dangerous action
        that was returned with needs_confirmation=True.
        """
        if any(b in action_value for b in self._BLOCKED_COMMANDS):
            return {"success": False, "error": "Command is permanently blocked"}
        return await self.run_command(action_value, timeout=120)

    # -- 6a. Window-Aware Automation ----------------------------------------

    async def automate_window(self, window_name: str, actions: list[dict]) -> dict:
        """Find a window by name and perform a sequence of actions on it."""
        windows = await self.find_window(window_name)
        if not windows:
            return {"success": False, "error": f"Window not found: {window_name}"}
        wid = windows[0]["window_id"]
        await self.focus_window(wid)
        await asyncio.sleep(0.3)  # Wait for focus
        results = []
        for action in actions:
            r = await self._dispatch_action(action.get("kind", ""), action)
            results.append(r)
            if action.get("delay"):
                await asyncio.sleep(action["delay"])
        return {"success": True, "window": windows[0], "results": results}

    # -- 6b. Clipboard Automation -------------------------------------------

    async def get_clipboard(self) -> dict:
        """Get clipboard contents."""
        env = _display_env()
        r = await _run_exec(["xclip", "-selection", "clipboard", "-o"], env=env)
        return {"success": r["returncode"] == 0, "content": r["stdout"]}

    async def set_clipboard(self, text: str) -> dict:
        """Set clipboard contents."""
        env = _display_env()
        r = await _run_exec(["xclip", "-selection", "clipboard"],
                            env=env, stdin_data=text.encode())
        return {"success": r["returncode"] == 0}

    # -- 6c. Screen Region OCR ----------------------------------------------

    async def read_screen_text(self, region: dict = None) -> dict:
        """OCR a screen region to extract text (requires tesseract)."""
        ss = await self.screenshot(region=region)
        if not ss.get("success"):
            return {"success": False, "error": "Screenshot failed"}
        r = await _run_exec(["tesseract", ss["path"], "-", "--psm", "6"],
                            timeout=30)
        return {"success": r["returncode"] == 0, "text": r["stdout"]}

    # -- 6d. Conditional Automation -----------------------------------------

    async def wait_for_window(self, name: str, timeout: int = 30) -> dict:
        """Wait for a window with the given name to appear."""
        start = time.time()
        while time.time() - start < timeout:
            windows = await self.find_window(name)
            if windows:
                return {"success": True, "window": windows[0]}
            await asyncio.sleep(0.5)
        return {"success": False,
                "error": f"Window '{name}' did not appear within {timeout}s"}

    # -- 7. Pipeline System -------------------------------------------------

    async def run_pipeline(self, pipeline: Pipeline) -> dict:
        results = []
        for i, action in enumerate(pipeline.actions):
            r = await self._dispatch_action(action.kind, action.params)
            results.append({"step": i, "kind": action.kind, **r})
            if not r.get("success", True) and r.get("returncode", 0) != 0:
                return {"success": False, "failed_at": i, "results": results}
        return {"success": True, "steps": len(results), "results": results}

    async def run_pipeline_json(self, actions: list[dict]) -> dict:
        """Run a pipeline from a JSON list: [{"kind": "launch", "app": "firefox"}, ...]"""
        return await self.run_pipeline(Pipeline(actions=[Action(a.pop("kind"), **a) for a in actions]))

    async def _dispatch_action(self, kind: str, params: dict) -> dict:
        dispatch = {
            "launch":      lambda p: self.launch_app(p.get("app", ""), p.get("args")),
            "type":        lambda p: self.type_text(p.get("text", "")),
            "press":       lambda p: self.press_key(p.get("key", "")),
            "click":       lambda p: self.click(p.get("x", 0), p.get("y", 0), p.get("button", 1)),
            "screenshot":  lambda p: self.screenshot(path=p.get("path")),
            "focus":       lambda p: self.focus_window(p.get("window_id", "")),
            "find_window": lambda p: self._dispatch_find(p),
            "move_window": lambda p: self.move_window(p.get("window_id", ""), p.get("x", 0),
                                                       p.get("y", 0), p.get("w"), p.get("h")),
            "command":     lambda p: self.run_command(p.get("cmd", ""), timeout=p.get("timeout", 30)),
            "shortcut":    lambda p: self.app_shortcut(p.get("app", ""), p.get("shortcut", "")),
            "route":       lambda p: self.route(p.get("instruction", "")),
            "automate_window": lambda p: self.automate_window(p.get("name", ""), p.get("actions", [])),
            "get_clipboard":   lambda p: self.get_clipboard(),
            "set_clipboard":   lambda p: self.set_clipboard(p.get("text", "")),
            "read_screen":     lambda p: self.read_screen_text(p.get("region")),
            "wait_window":     lambda p: self.wait_for_window(p.get("name", ""), p.get("timeout", 30)),
        }
        if kind == "wait":
            await asyncio.sleep(params.get("seconds", 1))
            return {"success": True}
        handler = dispatch.get(kind)
        if handler:
            return await handler(params)
        return {"success": False, "error": f"Unknown action kind: {kind}"}

    async def _dispatch_find(self, p: dict) -> dict:
        return {"success": True, "windows": await self.find_window(p.get("name", ""))}

    # -- 7. Workflow Templates ---------------------------------------------------

    WORKFLOWS: dict[str, dict] = {
        "setup_dev": {
            "name": "Developer Setup",
            "description": "Install common dev tools and configure environment",
            "steps": [
                {"kind": "command", "cmd": "sudo pacman -S --noconfirm --needed base-devel git python python-pip nodejs npm"},
                {"kind": "command", "cmd": "sudo pacman -S --noconfirm --needed code firefox"},
                {"kind": "launch", "app": "code"},
            ]
        },
        "gaming_setup": {
            "name": "Gaming Setup",
            "description": "Install gaming dependencies and configure",
            "steps": [
                {"kind": "command", "cmd": "sudo pacman -S --noconfirm --needed steam lutris wine-staging"},
                {"kind": "command", "cmd": "sudo pacman -S --noconfirm --needed lib32-vulkan-icd-loader lib32-mesa vulkan-tools"},
                {"kind": "launch", "app": "steam"},
            ]
        },
        "clean_system": {
            "name": "System Cleanup",
            "description": "Clean package cache, orphans, temp files",
            "steps": [
                {"kind": "command", "cmd": "sudo pacman -Sc --noconfirm"},
                {"kind": "command", "cmd": "sudo pacman -Rns $(pacman -Qdtq) --noconfirm 2>/dev/null || true"},
                {"kind": "command", "cmd": "rm -rf ~/.cache/thumbnails/*"},
                {"kind": "command", "cmd": "journalctl --vacuum-time=7d"},
            ]
        },
        "backup_home": {
            "name": "Backup Home Directory",
            "description": "Create a compressed backup of the home directory",
            "steps": [
                {"kind": "command", "cmd": "tar czf /tmp/home-backup-$(date +%Y%m%d).tar.gz -C /home arch --exclude='.cache' --exclude='.steam'"},
            ]
        },
        "network_diag": {
            "name": "Network Diagnostics",
            "description": "Run comprehensive network diagnostics",
            "steps": [
                {"kind": "command", "cmd": "ip addr show"},
                {"kind": "command", "cmd": "ip route show"},
                {"kind": "command", "cmd": "cat /etc/resolv.conf"},
                {"kind": "command", "cmd": "ping -c 3 8.8.8.8"},
                {"kind": "command", "cmd": "ping -c 3 google.com"},
                {"kind": "command", "cmd": "ss -tulpn"},
            ]
        },
        "screenshot_workflow": {
            "name": "Screenshot and Share",
            "description": "Take screenshot, open in viewer",
            "steps": [
                {"kind": "screenshot"},
                {"kind": "wait", "seconds": 1},
                {"kind": "command", "cmd": "xdg-open ~/Pictures/screenshot_*.png"},
            ]
        },
    }

    def get_workflows(self) -> dict:
        """Return all workflow templates."""
        return self.WORKFLOWS

    def get_workflow(self, name: str) -> dict:
        """Return a single workflow template by name, or None."""
        return self.WORKFLOWS.get(name)

    async def run_workflow(self, name: str, caller_trust: int = 400) -> dict:
        """Run a named workflow template."""
        wf = self.WORKFLOWS.get(name)
        if not wf:
            return {"success": False, "error": f"Unknown workflow: {name}",
                    "available": list(self.WORKFLOWS.keys())}
        return await self.run_pipeline_json([dict(s) for s in wf["steps"]])
