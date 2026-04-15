"""
compositor.py - Window compositor IPC controller

Provides window management via Hyprland IPC (Wayland) or wmctrl/xdotool (X11).
Auto-detects the active compositor.
"""

import os
import json
import shutil
import socket
import subprocess
import logging
import time
from typing import Optional

logger = logging.getLogger("ai-control.compositor")

# Cache for _detect_compositor(): environment rarely changes after daemon
# startup, so caching avoids 2 env dict lookups per window/workspace call.
# TTL = 30s keeps us responsive to session changes without constant work.
_compositor_cache: tuple[str, float] | None = None
_COMPOSITOR_TTL = 30.0

# Cache for `shutil.which(...)` binary lookups — PATH walks are real syscall
# cost on slow disks. These binaries don't come and go at runtime.
_which_cache: dict[str, Optional[str]] = {}


def _detect_compositor() -> str:
    """Detect whether we're running Hyprland, X11, or neither."""
    global _compositor_cache
    now = time.monotonic()
    if _compositor_cache is not None and (now - _compositor_cache[1]) < _COMPOSITOR_TTL:
        return _compositor_cache[0]
    if os.environ.get("HYPRLAND_INSTANCE_SIGNATURE"):
        result = "hyprland"
    elif os.environ.get("DISPLAY"):
        result = "x11"
    else:
        result = "none"
    _compositor_cache = (result, now)
    return result


def _which_cached(binary: str) -> Optional[str]:
    """Cached `shutil.which` — avoids PATH walks on hot paths."""
    if binary in _which_cache:
        return _which_cache[binary]
    path = shutil.which(binary)
    _which_cache[binary] = path
    return path


_hypr_sock_cache: tuple[str, str] | None = None  # (sig, resolved_path)

# Short-TTL cache for get_windows / get_workspaces / get_active_window.
# Desktop panels and Contusion can poll these 2-5× per second — the
# underlying subprocess/IPC call is ~5-15 ms each, so caching 500 ms
# saves 10-50 subprocess forks per second on old hardware.
_WINDOW_LIST_TTL = 0.5  # 500 ms
_windows_cache: tuple[list, float] | None = None
_active_window_cache: tuple[Optional[dict], float] | None = None
_workspaces_cache: tuple[list, float] | None = None


def _hyprland_ipc(command: str) -> str:
    """Send a command to Hyprland via its UNIX socket."""
    global _hypr_sock_cache
    sig = os.environ.get("HYPRLAND_INSTANCE_SIGNATURE", "")
    if _hypr_sock_cache is not None and _hypr_sock_cache[0] == sig:
        sock_path = _hypr_sock_cache[1]
    else:
        sock_path = f"/tmp/hypr/{sig}/.socket.sock"
        if not os.path.exists(sock_path):
            # Try XDG_RUNTIME_DIR
            xdg = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
            sock_path = f"{xdg}/hypr/{sig}/.socket.sock"
        _hypr_sock_cache = (sig, sock_path)

    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # 500ms timeout — fast fail if Hyprland is unresponsive
        sock.connect(sock_path)
        sock.send((command + "\n").encode())
        response = b""
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                logger.warning("Hyprland IPC recv timed out for command: %s", command)
                break
            if not data:
                break
            response += data
        return response.decode(errors="replace")
    except socket.timeout:
        logger.warning("Hyprland IPC connect timed out (socket: %s)", sock_path)
        return ""
    except OSError as e:
        logger.debug("Hyprland IPC unavailable: %s", e)
        return ""
    except Exception as e:
        logger.error("Hyprland IPC error: %s", e)
        return ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _hyprctl(args: str, json_output: bool = True) -> str:
    """Run hyprctl command.

    Args:
        args: Command string (split on whitespace).
        json_output: If True, pass -j for JSON output.  Disable for
                     dispatch/keyword commands that don't return JSON.
    """
    try:
        cmd = ["hyprctl"]
        if json_output:
            cmd.append("-j")
        cmd.extend(args.split())
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=5
        )
        return result.stdout
    except FileNotFoundError:
        logger.debug("hyprctl not found on PATH")
        return ""
    except Exception as e:
        logger.error("hyprctl error: %s", e)
        return ""


def get_windows() -> list:
    """Get list of open windows. Cached for _WINDOW_LIST_TTL seconds."""
    global _windows_cache
    now = time.monotonic()
    if _windows_cache is not None and (now - _windows_cache[1]) < _WINDOW_LIST_TTL:
        return _windows_cache[0]

    compositor = _detect_compositor()
    result: list = []

    if compositor == "hyprland":
        try:
            data = _hyprctl("clients")
            result = json.loads(data) if data else []
        except json.JSONDecodeError:
            result = []

    elif compositor == "x11":
        if not _which_cached("wmctrl"):
            logger.debug("wmctrl not found on PATH; cannot list X11 windows")
            _windows_cache = ([], now)
            return []
        try:
            sub_result = subprocess.run(
                ["wmctrl", "-l", "-p"], capture_output=True, text=True, timeout=5
            )
            for line in sub_result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split(None, 4)
                if len(parts) >= 5:
                    result.append({
                        "id": parts[0],
                        "desktop": parts[1],
                        "pid": parts[2],
                        "host": parts[3],
                        "title": parts[4],
                    })
                elif len(parts) == 4:
                    result.append({
                        "id": parts[0],
                        "desktop": parts[1],
                        "pid": parts[2],
                        "host": parts[3],
                        "title": "",
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.debug("wmctrl failed: %s", e)

    _windows_cache = (result, now)
    return result


def get_active_window() -> Optional[dict]:
    """Get the currently focused window. Cached for _WINDOW_LIST_TTL seconds."""
    global _active_window_cache
    now = time.monotonic()
    if _active_window_cache is not None and (now - _active_window_cache[1]) < _WINDOW_LIST_TTL:
        return _active_window_cache[0]

    compositor = _detect_compositor()
    result: Optional[dict] = None

    if compositor == "hyprland":
        try:
            data = _hyprctl("activewindow")
            result = json.loads(data) if data else None
        except json.JSONDecodeError:
            result = None

    elif compositor == "x11":
        if not _which_cached("xdotool"):
            logger.debug("xdotool not found on PATH; cannot get active window")
            _active_window_cache = (None, now)
            return None
        try:
            sub_result = subprocess.run(
                ["xdotool", "getactivewindow", "getwindowname"],
                capture_output=True, text=True, timeout=5
            )
            result = {"title": sub_result.stdout.strip()} if sub_result.returncode == 0 else None
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.debug("xdotool failed: %s", e)

    _active_window_cache = (result, now)
    return result


def _invalidate_window_caches() -> None:
    """Drop window/active/workspace caches after a mutating op."""
    global _windows_cache, _active_window_cache, _workspaces_cache
    _windows_cache = None
    _active_window_cache = None
    _workspaces_cache = None


def focus_window(identifier: str) -> bool:
    """Focus a window by ID or title."""
    compositor = _detect_compositor()
    _invalidate_window_caches()

    if compositor == "hyprland":
        result = _hyprctl(f"dispatch focuswindow address:{identifier}",
                          json_output=False)
        return bool(result) or result == ""  # Hyprland returns "ok" or empty on success
    elif compositor == "x11":
        try:
            r = subprocess.run(["wmctrl", "-i", "-a", identifier],
                               capture_output=True, timeout=5)
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.debug("wmctrl not found or timed out")
            return False
    return False


def close_window(identifier: str) -> bool:
    """Close a window."""
    compositor = _detect_compositor()
    _invalidate_window_caches()

    if compositor == "hyprland":
        _hyprctl(f"dispatch closewindow address:{identifier}",
                 json_output=False)
        return True
    elif compositor == "x11":
        try:
            r = subprocess.run(["wmctrl", "-i", "-c", identifier],
                               capture_output=True, timeout=5)
            return r.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.debug("wmctrl not found or timed out")
            return False
    return False


def set_layout(layout: str) -> dict:
    """Apply a predefined window layout."""
    compositor = _detect_compositor()
    layouts = {
        "productivity": "dwindle",
        "gaming": "master",
        "presentation": "master",
        "tiling": "dwindle",
    }

    if compositor == "hyprland":
        hypr_layout = layouts.get(layout, "dwindle")
        _hyprctl(f"keyword general:layout {hypr_layout}", json_output=False)
        return {"status": "ok", "layout": layout, "compositor": "hyprland"}
    elif compositor == "x11":
        return {"status": "ok", "layout": layout, "note": "X11 tiling managed by WM"}

    return {"status": "error", "message": "No compositor detected"}


def get_workspaces() -> list:
    """Get workspace/desktop list. Cached for _WINDOW_LIST_TTL seconds."""
    global _workspaces_cache
    now = time.monotonic()
    if _workspaces_cache is not None and (now - _workspaces_cache[1]) < _WINDOW_LIST_TTL:
        return _workspaces_cache[0]

    compositor = _detect_compositor()
    desktops: list = []

    if compositor == "hyprland":
        try:
            data = _hyprctl("workspaces")
            desktops = json.loads(data) if data else []
        except json.JSONDecodeError:
            desktops = []
    elif compositor == "x11":
        if not _which_cached("wmctrl"):
            logger.debug("wmctrl not found on PATH; cannot list workspaces")
            _workspaces_cache = ([], now)
            return []
        try:
            result = subprocess.run(
                ["wmctrl", "-d"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split(None, 8)
                if len(parts) >= 9:
                    desktops.append({
                        "id": parts[0],
                        "active": parts[1] == "*",
                        "name": parts[8],
                    })
                elif len(parts) >= 2:
                    desktops.append({
                        "id": parts[0],
                        "active": parts[1] == "*",
                        "name": f"Desktop {parts[0]}",
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.debug("wmctrl -d failed: %s", e)

    _workspaces_cache = (desktops, now)
    return desktops


def get_info() -> dict:
    """Get compositor info."""
    compositor = _detect_compositor()
    return {
        "compositor": compositor,
        "session_type": os.environ.get("XDG_SESSION_TYPE", "unknown"),
        "display": os.environ.get("DISPLAY", ""),
        "wayland_display": os.environ.get("WAYLAND_DISPLAY", ""),
    }
