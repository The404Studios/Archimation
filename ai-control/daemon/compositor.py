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
from typing import Optional

logger = logging.getLogger("ai-control.compositor")


def _detect_compositor() -> str:
    """Detect whether we're running Hyprland, X11, or neither."""
    if os.environ.get("HYPRLAND_INSTANCE_SIGNATURE"):
        return "hyprland"
    if os.environ.get("DISPLAY"):
        return "x11"
    return "none"


def _hyprland_ipc(command: str) -> str:
    """Send a command to Hyprland via its UNIX socket."""
    sig = os.environ.get("HYPRLAND_INSTANCE_SIGNATURE", "")
    sock_path = f"/tmp/hypr/{sig}/.socket.sock"
    if not os.path.exists(sock_path):
        # Try XDG_RUNTIME_DIR
        xdg = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        sock_path = f"{xdg}/hypr/{sig}/.socket.sock"

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
    """Get list of open windows."""
    compositor = _detect_compositor()

    if compositor == "hyprland":
        try:
            data = _hyprctl("clients")
            return json.loads(data) if data else []
        except json.JSONDecodeError:
            return []

    elif compositor == "x11":
        if not shutil.which("wmctrl"):
            logger.debug("wmctrl not found on PATH; cannot list X11 windows")
            return []
        try:
            result = subprocess.run(
                ["wmctrl", "-l", "-p"], capture_output=True, text=True, timeout=5
            )
            windows = []
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split(None, 4)
                if len(parts) >= 5:
                    windows.append({
                        "id": parts[0],
                        "desktop": parts[1],
                        "pid": parts[2],
                        "host": parts[3],
                        "title": parts[4],
                    })
                elif len(parts) == 4:
                    windows.append({
                        "id": parts[0],
                        "desktop": parts[1],
                        "pid": parts[2],
                        "host": parts[3],
                        "title": "",
                    })
            return windows
        except Exception as e:
            logger.debug("wmctrl failed: %s", e)
            return []

    return []


def get_active_window() -> Optional[dict]:
    """Get the currently focused window."""
    compositor = _detect_compositor()

    if compositor == "hyprland":
        try:
            data = _hyprctl("activewindow")
            return json.loads(data) if data else None
        except json.JSONDecodeError:
            return None

    elif compositor == "x11":
        if not shutil.which("xdotool"):
            logger.debug("xdotool not found on PATH; cannot get active window")
            return None
        try:
            result = subprocess.run(
                ["xdotool", "getactivewindow", "getwindowname"],
                capture_output=True, text=True, timeout=5
            )
            return {"title": result.stdout.strip()} if result.returncode == 0 else None
        except Exception as e:
            logger.debug("xdotool failed: %s", e)
            return None

    return None


def focus_window(identifier: str) -> bool:
    """Focus a window by ID or title."""
    compositor = _detect_compositor()

    if compositor == "hyprland":
        result = _hyprctl(f"dispatch focuswindow address:{identifier}",
                          json_output=False)
        return bool(result) or result == ""  # Hyprland returns "ok" or empty on success
    elif compositor == "x11":
        try:
            r = subprocess.run(["wmctrl", "-i", "-a", identifier],
                               capture_output=True, timeout=5)
            return r.returncode == 0
        except FileNotFoundError:
            logger.debug("wmctrl not found on PATH")
            return False
        except Exception:
            return False
    return False


def close_window(identifier: str) -> bool:
    """Close a window."""
    compositor = _detect_compositor()

    if compositor == "hyprland":
        _hyprctl(f"dispatch closewindow address:{identifier}",
                 json_output=False)
        return True
    elif compositor == "x11":
        try:
            r = subprocess.run(["wmctrl", "-i", "-c", identifier],
                               capture_output=True, timeout=5)
            return r.returncode == 0
        except FileNotFoundError:
            logger.debug("wmctrl not found on PATH")
            return False
        except Exception:
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
    """Get workspace/desktop list."""
    compositor = _detect_compositor()

    if compositor == "hyprland":
        try:
            data = _hyprctl("workspaces")
            return json.loads(data) if data else []
        except json.JSONDecodeError:
            return []
    elif compositor == "x11":
        if not shutil.which("wmctrl"):
            logger.debug("wmctrl not found on PATH; cannot list workspaces")
            return []
        try:
            result = subprocess.run(
                ["wmctrl", "-d"], capture_output=True, text=True, timeout=5
            )
            desktops = []
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
            return desktops
        except Exception as e:
            logger.debug("wmctrl -d failed: %s", e)
            return []
    return []


def get_info() -> dict:
    """Get compositor info."""
    compositor = _detect_compositor()
    return {
        "compositor": compositor,
        "session_type": os.environ.get("XDG_SESSION_TYPE", "unknown"),
        "display": os.environ.get("DISPLAY", ""),
        "wayland_display": os.environ.get("WAYLAND_DISPLAY", ""),
    }
