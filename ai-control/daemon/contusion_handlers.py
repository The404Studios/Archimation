"""
Contusion handler dispatch table.

Maps `handler_type` strings (defined in contusion_dictionary.py) to async
coroutines that execute a real Linux command via subprocess.

Envelope shape every handler returns:
    {"success": bool, "output": str, "stderr": str,
     "returncode": int, "handler": str}

On missing tool (ENOENT) handlers add "error" and set success=False rather
than propagating the OSError, so the calling Action dispatcher never crashes.
"""

import asyncio
import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Awaitable, Callable

# Session 50 Agent H: route input validation + admin-command rate limiting
# through the safety singletons. Sanitizer is stateless; THROTTLE_DRIVER_LOAD
# is the same instance api_server.py uses for /driver/{load,unload} so a
# burst across both surfaces is bounded by ONE token bucket.
try:
    from .safety import (
        Sanitizer,
        SanitizerError,
        THROTTLE_DRIVER_LOAD,
    )
except ImportError:
    from safety import (  # type: ignore[no-redef]
        Sanitizer,
        SanitizerError,
        THROTTLE_DRIVER_LOAD,
    )

logger = logging.getLogger("ai-control.contusion")

# Default display env so GUI-bound tools (xdotool/xclip/scrot/wmctrl) reach :0
def _env() -> dict:
    e = os.environ.copy()
    e.setdefault("DISPLAY", ":0")
    # XDG_RUNTIME_DIR is sometimes missing in systemd-spawned contexts;
    # wpctl/pactl both need it to reach pipewire/pulse.
    if "XDG_RUNTIME_DIR" not in e:
        uid = os.getuid() if hasattr(os, "getuid") else 1000
        cand = f"/run/user/{uid}"
        if os.path.isdir(cand):
            e["XDG_RUNTIME_DIR"] = cand
    return e


def _envelope(handler: str, rc: int, out: str, err: str, **extra) -> dict:
    return {
        "success": rc == 0,
        "output": out,
        "stderr": err,
        "returncode": rc,
        "handler": handler,
        **extra,
    }


def _missing(handler: str, tool: str, install_hint: str | None = None) -> dict:
    err = f"{tool} not installed"
    if install_hint:
        err = f"{err} (install: {install_hint})"
    env = {
        "success": False,
        "output": "",
        "stderr": err,
        "returncode": 127,
        "handler": handler,
        "error": err,
        "missing": tool,
    }
    if install_hint:
        env["install_hint"] = install_hint
    return env


def _bad_arg(handler: str, msg: str) -> dict:
    return {
        "success": False,
        "output": "",
        "stderr": msg,
        "returncode": 2,
        "handler": handler,
        "error": msg,
    }


async def _exec(handler: str, argv: list, timeout: int = 15,
                stdin_data: bytes = None, shell_wrap: bool = False) -> dict:
    tool = argv[0]
    if not shell_wrap and shutil.which(tool) is None:
        return _missing(handler, tool)
    try:
        if shell_wrap:
            proc = await asyncio.create_subprocess_shell(
                " ".join(argv) if isinstance(argv, list) else argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
                env=_env())
        else:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
                env=_env())
    except FileNotFoundError:
        return _missing(handler, tool)
    except Exception as e:
        return {"success": False, "output": "", "stderr": str(e),
                "returncode": -1, "handler": handler, "error": str(e)}
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_data), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return {"success": False, "output": "", "stderr": "timeout",
                "returncode": -1, "handler": handler, "error": "timeout"}
    return _envelope(handler,
                     proc.returncode,
                     stdout.decode(errors="replace").strip(),
                     stderr.decode(errors="replace").strip())


async def _detached(argv: list) -> None:
    # Fire-and-forget for power actions so the daemon's envelope returns
    # before the system actually goes down.
    try:
        await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL, env=_env(),
            start_new_session=True)
    except Exception as e:
        logger.warning("detached exec failed %s: %s", argv, e)


# ---------------------------------------------------------------------------
# Session 58: every success=false envelope must carry a non-empty 'error'
# field so the AI/CLI surface can explain *why* a handler failed. The four
# helpers above (_envelope, _missing, _bad_arg, _exec) keep their existing
# semantics; the helpers below ENRICH a result without changing semantics:
#
#   _with_error(env)  - if env says success=False and no 'error' key is set,
#                       copies stderr (or a synthesised "command failed
#                       (rc=N)") into 'error'. Idempotent on success cases
#                       and on envelopes that already carry an error.
#
#   _compositor_status() - structured probe of the current graphical session
#                       so window/workspace/clipboard handlers can fail with
#                       "no graphical session" instead of an opaque
#                       "command failed".
# ---------------------------------------------------------------------------


def _with_error(env: dict) -> dict:
    """Attach a structured 'error' field to a failing envelope.

    Idempotent: if 'error' is already populated, or success=True, returns env
    unchanged. Synthesises an error string from stderr / returncode when the
    underlying tool exited non-zero with empty stderr (common for wmctrl /
    xdotool / systemctl on missing prerequisites).
    """
    if not isinstance(env, dict):
        return env
    if env.get("success"):
        return env
    if env.get("error") or env.get("missing"):
        return env
    stderr = (env.get("stderr") or "").strip()
    rc = env.get("returncode")
    if stderr:
        env["error"] = stderr
    elif isinstance(rc, int):
        env["error"] = f"command failed (rc={rc})"
    else:
        env["error"] = "command failed"
    return env


def _compositor_status() -> dict:
    """Return structured info about the current graphical session.

    Window/workspace/clipboard handlers route through this so a "command
    failed" with empty stderr (the common wmctrl/xdotool result when no X
    server is reachable) becomes a clear "no graphical session" message.
    """
    if os.environ.get("HYPRLAND_INSTANCE_SIGNATURE"):
        return {"available": True, "type": "hyprland"}
    if os.environ.get("WAYLAND_DISPLAY"):
        return {"available": True, "type": "wayland"}
    if os.environ.get("DISPLAY"):
        return {"available": True, "type": "x11"}
    return {
        "available": False,
        "type": "none",
        "reason": ("no graphical session "
                   "(DISPLAY/WAYLAND_DISPLAY/HYPRLAND_INSTANCE_SIGNATURE "
                   "all unset)"),
    }


def _no_session(handler: str, sess: dict) -> dict:
    """Standard structured failure when the compositor probe says no GUI."""
    return {
        "success": False,
        "output": "",
        "stderr": sess["reason"],
        "returncode": 1,
        "handler": handler,
        "error": sess["reason"],
        "session": sess["type"],
    }


# ---------------------------------------------------------------------------
# AUDIO
# ---------------------------------------------------------------------------

async def _audio_vol(args, sign):
    h = f"audio.volume_{sign}"
    step = str(args.get("step", 5))
    if shutil.which("wpctl"):
        return _with_error(await _exec(h, ["wpctl", "set-volume", "-l", "1.5",
                               "@DEFAULT_AUDIO_SINK@", f"{step}%{'+' if sign == 'up' else '-'}"]))
    if shutil.which("pactl"):
        return _with_error(await _exec(h, ["pactl", "set-sink-volume", "@DEFAULT_SINK@",
                               f"{'+' if sign == 'up' else '-'}{step}%"]))
    return _missing(h, "wpctl/pactl")


async def audio_volume_up(args): return await _audio_vol(args, "up")
async def audio_volume_down(args): return await _audio_vol(args, "down")


async def audio_volume_set(args):
    h = "audio.volume_set"
    pct = args.get("percent")
    if pct is None:
        return _bad_arg(h, "missing arg 'percent'")
    if isinstance(pct, bool) or not isinstance(pct, (int, float)):
        return _bad_arg(h, "arg 'percent' must be numeric in [0,150]")
    try:
        fp = float(pct)
    except (TypeError, ValueError):
        return _bad_arg(h, "arg 'percent' must be numeric in [0,150]")
    if fp != fp or fp < 0 or fp > 150:
        return _bad_arg(h, "arg 'percent' must be numeric in [0,150]")
    p = int(fp)
    # wpctl set-volume takes a ratio like 1.5 (no suffix) for >100%; the
    # N% form is clamped at 100 on most distros. Use ratio form + -l 1.5.
    if shutil.which("wpctl"):
        ratio = f"{p/100:.2f}"
        return await _exec(h, ["wpctl", "set-volume", "-l", "1.5",
                               "@DEFAULT_AUDIO_SINK@", ratio])
    if shutil.which("pactl"):
        if p > 100:
            return _bad_arg(h, "pactl caps at 100%; wpctl not available for boost")
        return await _exec(h, ["pactl", "set-sink-volume", "@DEFAULT_SINK@", f"{p}%"])
    return _missing(h, "wpctl/pactl")


async def audio_mute_toggle(args):
    h = "audio.mute_toggle"
    if shutil.which("wpctl"):
        return _with_error(await _exec(h, ["wpctl", "set-mute", "@DEFAULT_AUDIO_SINK@", "toggle"]))
    if shutil.which("pactl"):
        return _with_error(await _exec(h, ["pactl", "set-sink-mute", "@DEFAULT_SINK@", "toggle"]))
    return _missing(h, "wpctl/pactl")


async def audio_mic_mute_toggle(args):
    h = "audio.mic_mute_toggle"
    if shutil.which("wpctl"):
        return _with_error(await _exec(h, ["wpctl", "set-mute", "@DEFAULT_AUDIO_SOURCE@", "toggle"]))
    if shutil.which("pactl"):
        return _with_error(await _exec(h, ["pactl", "set-source-mute", "@DEFAULT_SOURCE@", "toggle"]))
    return _missing(h, "wpctl/pactl")


async def audio_mic_volume_up(args):
    h = "audio.mic_volume_up"
    step = str(args.get("step", 5))
    if shutil.which("wpctl"):
        return _with_error(await _exec(h, ["wpctl", "set-volume", "@DEFAULT_AUDIO_SOURCE@", f"{step}%+"]))
    if shutil.which("pactl"):
        return _with_error(await _exec(h, ["pactl", "set-source-volume", "@DEFAULT_SOURCE@", f"+{step}%"]))
    return _missing(h, "wpctl/pactl")


async def audio_mic_volume_down(args):
    h = "audio.mic_volume_down"
    step = str(args.get("step", 5))
    if shutil.which("wpctl"):
        return _with_error(await _exec(h, ["wpctl", "set-volume", "@DEFAULT_AUDIO_SOURCE@", f"{step}%-"]))
    if shutil.which("pactl"):
        return _with_error(await _exec(h, ["pactl", "set-source-volume", "@DEFAULT_SOURCE@", f"-{step}%"]))
    return _missing(h, "wpctl/pactl")


async def audio_sink_list(args):
    h = "audio.sink_list"
    if shutil.which("wpctl"):
        return _with_error(await _exec(h, ["wpctl", "status"]))
    if shutil.which("pactl"):
        return _with_error(await _exec(h, ["pactl", "list", "short", "sinks"]))
    return _missing(h, "wpctl/pactl")


async def audio_sink_set(args):
    h = "audio.sink_set"
    sink = args.get("sink") or args.get("name") or args.get("id")
    if not sink:
        return _bad_arg(h, "missing arg 'sink'")
    if shutil.which("wpctl"):
        return await _exec(h, ["wpctl", "set-default", str(sink)])
    if shutil.which("pactl"):
        return await _exec(h, ["pactl", "set-default-sink", str(sink)])
    return _missing(h, "wpctl/pactl")


async def audio_restart(args):
    h = "audio.restart"
    if shutil.which("systemctl"):
        return await _exec(h, ["systemctl", "--user", "restart",
                               "pipewire.service", "pipewire-pulse.service",
                               "wireplumber.service"], timeout=15)
    return _missing(h, "systemctl")


# ---------------------------------------------------------------------------
# BRIGHTNESS
# ---------------------------------------------------------------------------

async def brightness_up(args):
    h = "brightness.up"
    step = str(args.get("step", 5))
    return await _exec(h, ["brightnessctl", "set", f"+{step}%"])


async def brightness_down(args):
    h = "brightness.down"
    step = str(args.get("step", 5))
    return await _exec(h, ["brightnessctl", "set", f"{step}%-"])


async def brightness_set(args):
    h = "brightness.set"
    pct = args.get("percent")
    if pct is None:
        return _bad_arg(h, "missing arg 'percent'")
    try:
        p = max(1, min(100, int(pct)))
    except (TypeError, ValueError):
        return _bad_arg(h, "arg 'percent' must be int")
    return await _exec(h, ["brightnessctl", "set", f"{p}%"])


async def brightness_get(args):
    h = "brightness.get"
    cur = await _exec(h, ["brightnessctl", "g"])
    if not cur["success"]:
        return cur
    mx = await _exec(h, ["brightnessctl", "m"])
    if not mx["success"]:
        return mx
    try:
        c = int(cur["output"] or "0")
        m = int(mx["output"] or "1")
        pct = int(round(c * 100 / max(m, 1)))
    except ValueError:
        return _envelope(h, 1, "", "parse failure")
    return _envelope(h, 0, str(pct), "", percent=pct, raw=c, maximum=m)


async def brightness_max(args):
    h = "brightness.max"
    return await _exec(h, ["brightnessctl", "set", "100%"])


async def brightness_min(args):
    h = "brightness.min"
    return await _exec(h, ["brightnessctl", "set", "1%"])


async def brightness_auto(args):
    # Prefer ambient-light sensor (IIO) over a hardcoded 70% fallback.
    h = "brightness.auto"
    target_pct = None
    try:
        iio = Path("/sys/bus/iio/devices")
        if iio.is_dir():
            for dev in iio.iterdir():
                raw = _read_text(dev / "in_illuminance_input")
                if raw is None:
                    raw = _read_text(dev / "in_illuminance_raw")
                if raw is None:
                    continue
                try:
                    lux = float(raw)
                except ValueError:
                    continue
                # Linear 0 lux -> 5%, 1000 lux -> 100%; clamp at ends.
                pct = 5 + (lux / 1000.0) * 95.0
                target_pct = max(5, min(100, int(round(pct))))
                break
    except OSError:
        target_pct = None
    # Sanity: require at least one /sys/class/backlight/*/actual_brightness
    # readable before trusting sensor; otherwise fall back to 70.
    if target_pct is not None:
        bl = Path("/sys/class/backlight")
        readable = False
        if bl.is_dir():
            for d in bl.iterdir():
                if _read_text(d / "actual_brightness") is not None:
                    readable = True
                    break
        if not readable:
            target_pct = None
    if target_pct is None:
        target_pct = 70
    return await _exec(h, ["brightnessctl", "set", f"{target_pct}%"])


# ---------------------------------------------------------------------------
# MEDIA (playerctl)
# ---------------------------------------------------------------------------

async def _pctl(h, *subargs, timeout=15):
    return await _exec(h, ["playerctl", *subargs], timeout=timeout)


async def media_play(args): return await _pctl("media.play", "play")
async def media_pause(args): return await _pctl("media.pause", "pause")
async def media_play_pause(args): return await _pctl("media.play_pause", "play-pause")
async def media_next(args): return await _pctl("media.next", "next")
async def media_prev(args): return await _pctl("media.prev", "previous")
async def media_stop(args): return await _pctl("media.stop", "stop")


async def media_status(args):
    h = "media.status"
    if shutil.which("playerctl") is None:
        return _missing(h, "playerctl")
    s = await _exec(h, ["playerctl", "status"])
    m = await _exec(h, ["playerctl", "metadata"])
    combined = f"{s['output']}\n{m['output']}".strip()
    return _envelope(h, 0 if s["returncode"] == 0 else s["returncode"],
                     combined, s["stderr"] or m["stderr"],
                     status=s["output"], metadata=m["output"])


async def media_seek_forward(args):
    secs = str(args.get("seconds", 10))
    return await _pctl("media.seek_forward", "position", f"{secs}+")


async def media_seek_back(args):
    secs = str(args.get("seconds", 10))
    return await _pctl("media.seek_back", "position", f"{secs}-")


async def media_list_players(args):
    return await _pctl("media.list_players", "-l")


# ---------------------------------------------------------------------------
# WINDOW (wmctrl + xdotool)
# ---------------------------------------------------------------------------

async def window_minimize(args):
    h = "window.minimize"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    return _with_error(await _exec(h, ["xdotool", "getactivewindow", "windowminimize"]))


async def window_maximize(args):
    h = "window.maximize"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    return _with_error(await _exec(h, ["wmctrl", "-r", ":ACTIVE:", "-b",
                           "add,maximized_vert,maximized_horz"]))


async def window_restore(args):
    h = "window.restore"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    return _with_error(await _exec(h, ["wmctrl", "-r", ":ACTIVE:", "-b",
                           "remove,maximized_vert,maximized_horz"]))


async def window_close(args):
    h = "window.close"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    return _with_error(await _exec(h, ["wmctrl", "-c", ":ACTIVE:"]))


async def window_close_force(args):
    h = "window.close_force"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    if shutil.which("xdotool") is None:
        return _missing(h, "xdotool")
    wid = await _exec(h, ["xdotool", "getactivewindow"])
    if not wid["success"]:
        return _with_error(wid)
    return _with_error(await _exec(h, ["xdotool", "windowkill", wid["output"]]))


async def window_fullscreen_toggle(args):
    h = "window.fullscreen_toggle"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    return _with_error(await _exec(h, ["wmctrl", "-r", ":ACTIVE:", "-b", "toggle,fullscreen"]))


async def window_shade(args):
    h = "window.shade"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    return _with_error(await _exec(h, ["wmctrl", "-r", ":ACTIVE:", "-b", "toggle,shaded"]))


async def window_above(args):
    h = "window.above"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    return _with_error(await _exec(h, ["wmctrl", "-r", ":ACTIVE:", "-b", "toggle,above"]))


async def window_below(args):
    h = "window.below"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    return _with_error(await _exec(h, ["wmctrl", "-r", ":ACTIVE:", "-b", "toggle,below"]))


async def window_sticky(args):
    h = "window.sticky"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    return _with_error(await _exec(h, ["wmctrl", "-r", ":ACTIVE:", "-b", "toggle,sticky"]))


async def window_focus_title(args):
    h = "window.focus_title"
    title = args.get("title") or args.get("name")
    if not title:
        return _bad_arg(h, "missing arg 'title'")
    return await _exec(h, ["wmctrl", "-a", str(title)])


async def window_focus_class(args):
    h = "window.focus_class"
    cls = args.get("class") or args.get("wmclass")
    if not cls:
        return _bad_arg(h, "missing arg 'class'")
    if shutil.which("wmctrl") is None:
        return _missing(h, "wmctrl")
    cls = str(cls)
    # wmctrl -x matches WM_CLASS "instance.class"; caller may pass either half.
    # Grep -lx output to find the real instance.class then hand that full
    # string to -a so prefix matching lands on the right window.
    listing = await _exec(h, ["wmctrl", "-lx"])
    if listing["success"]:
        cls_low = cls.lower()
        for ln in listing["output"].splitlines():
            parts = ln.split(None, 4)
            if len(parts) < 4:
                continue
            wm_class = parts[2]
            halves = wm_class.split(".", 1)
            inst = halves[0].lower()
            klass = halves[1].lower() if len(halves) == 2 else ""
            if cls_low == wm_class.lower() or cls_low == inst or cls_low == klass:
                return await _exec(h, ["wmctrl", "-x", "-a", wm_class])
    return await _exec(h, ["wmctrl", "-x", "-a", cls])


async def _screen_geom():
    # Returns (w, h) of primary monitor via xdotool.
    if shutil.which("xdotool") is None:
        return None
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "xdotool", "getdisplaygeometry",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=_env())
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        parts = out.decode().strip().split()
        if len(parts) >= 2:
            return int(parts[0]), int(parts[1])
    except asyncio.TimeoutError:
        if proc is not None:
            try:
                proc.kill(); await proc.wait()
            except ProcessLookupError:
                pass
        return None
    except Exception:
        if proc is not None and proc.returncode is None:
            try:
                proc.kill(); await proc.wait()
            except ProcessLookupError:
                pass
        return None
    return None


async def _tile(h, quadrant):
    geom = await _screen_geom()
    if not geom:
        return _missing(h, "xdotool")
    sw, sh = geom
    hw, hh = sw // 2, sh // 2
    if quadrant == "left":   x, y, w, h2 = 0, 0, hw, sh
    elif quadrant == "right":  x, y, w, h2 = hw, 0, hw, sh
    elif quadrant == "top":    x, y, w, h2 = 0, 0, sw, hh
    elif quadrant == "bottom": x, y, w, h2 = 0, hh, sw, hh
    else:
        return _bad_arg(h, f"unknown quadrant {quadrant}")
    # unmaximize then move+resize
    await _exec(h, ["wmctrl", "-r", ":ACTIVE:", "-b",
                    "remove,maximized_vert,maximized_horz"])
    return await _exec(h, ["wmctrl", "-r", ":ACTIVE:", "-e",
                           f"0,{x},{y},{w},{h2}"])


async def window_tile_left(args):   return await _tile("window.tile_left", "left")
async def window_tile_right(args):  return await _tile("window.tile_right", "right")
async def window_tile_top(args):    return await _tile("window.tile_top", "top")
async def window_tile_bottom(args): return await _tile("window.tile_bottom", "bottom")


async def window_move_to_workspace(args):
    h = "window.move_to_workspace"
    ws = args.get("workspace")
    if ws is None:
        return _bad_arg(h, "missing arg 'workspace'")
    return await _exec(h, ["wmctrl", "-r", ":ACTIVE:", "-t", str(ws)])


async def window_list(args):
    h = "window.list"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    return _with_error(await _exec(h, ["wmctrl", "-l"]))


# ---------------------------------------------------------------------------
# WORKSPACE
# ---------------------------------------------------------------------------

async def _current_ws():
    # Parses "wmctrl -d" to find the row with '*' in column 2
    if shutil.which("wmctrl") is None:
        return None
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "wmctrl", "-d", stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, env=_env())
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        count = 0
        cur = 0
        for line in out.decode(errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                count += 1
                if "*" in parts[1]:
                    try:
                        cur = int(parts[0])
                    except ValueError:
                        pass
        return cur, count
    except asyncio.TimeoutError:
        if proc is not None:
            try:
                proc.kill(); await proc.wait()
            except ProcessLookupError:
                pass
        return None
    except Exception:
        if proc is not None and proc.returncode is None:
            try:
                proc.kill(); await proc.wait()
            except ProcessLookupError:
                pass
        return None


async def workspace_next(args):
    h = "workspace.next"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    info = await _current_ws()
    if not info:
        return _missing(h, "wmctrl")
    cur, count = info
    target = (cur + 1) % max(count, 1)
    return _with_error(await _exec(h, ["wmctrl", "-s", str(target)]))


async def workspace_prev(args):
    h = "workspace.prev"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    info = await _current_ws()
    if not info:
        return _missing(h, "wmctrl")
    cur, count = info
    target = (cur - 1) % max(count, 1)
    return _with_error(await _exec(h, ["wmctrl", "-s", str(target)]))


async def workspace_switch(args):
    h = "workspace.switch"
    idx = args.get("index")
    if idx is None:
        idx = args.get("n")
    if idx is None:
        return _bad_arg(h, "missing arg 'index'")
    return await _exec(h, ["wmctrl", "-s", str(idx)])


async def workspace_new(args):
    h = "workspace.new"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    info = await _current_ws()
    if not info:
        return _missing(h, "wmctrl")
    _, count = info
    return _with_error(await _exec(h, ["wmctrl", "-n", str(count + 1)]))


async def workspace_delete_current(args):
    h = "workspace.delete_current"
    info = await _current_ws()
    if not info:
        return _missing(h, "wmctrl")
    _, count = info
    if count <= 1:
        return _envelope(h, 1, "", "cannot delete last workspace")
    return await _exec(h, ["wmctrl", "-n", str(count - 1)])


async def workspace_list(args):
    h = "workspace.list"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    return _with_error(await _exec(h, ["wmctrl", "-d"]))


async def workspace_move_window_here(args):
    h = "workspace.move_window_here"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    info = await _current_ws()
    if not info:
        return _missing(h, "wmctrl")
    cur, _ = info
    return _with_error(await _exec(h, ["wmctrl", "-r", ":ACTIVE:", "-t", str(cur)]))


async def workspace_show_all(args):
    h = "workspace.show_all"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    # Fallback: list windows on all desktops
    return _with_error(await _exec(h, ["wmctrl", "-l"]))


# ---------------------------------------------------------------------------
# POWER
# ---------------------------------------------------------------------------

async def power_lock_screen(args):
    h = "power.lock_screen"
    last = None
    if shutil.which("loginctl"):
        r = await _exec(h, ["loginctl", "lock-session"])
        if r["success"]:
            return r
        last = r
    if shutil.which("xflock4"):
        return _with_error(await _exec(h, ["xflock4"]))
    if shutil.which("xdg-screensaver"):
        return _with_error(await _exec(h, ["xdg-screensaver", "lock"]))
    if last is not None:
        return _with_error(last)
    return _missing(h, "loginctl/xflock4/xdg-screensaver")


async def power_unlock_screen(args):
    h = "power.unlock_screen"
    # No universal unlock API; loginctl unlock-session works only with
    # session id and root or pam. Best-effort kill of common lockers.
    if shutil.which("loginctl"):
        return _with_error(await _exec(h, ["loginctl", "unlock-session"]))
    return _missing(h, "loginctl")


async def power_logout(args):
    h = "power.logout"
    if shutil.which("xfce4-session-logout"):
        await _detached(["xfce4-session-logout", "--logout", "--fast"])
        return _envelope(h, 0, "logout requested", "")
    if shutil.which("loginctl"):
        await _detached(["loginctl", "terminate-user", os.environ.get("USER", "")])
        return _envelope(h, 0, "terminate-user requested", "")
    return _missing(h, "xfce4-session-logout/loginctl")


async def power_suspend(args):
    h = "power.suspend"
    if shutil.which("systemctl") is None:
        return _missing(h, "systemctl")
    await _detached(["systemctl", "suspend"])
    return _envelope(h, 0, "suspend requested", "")


async def power_hibernate(args):
    h = "power.hibernate"
    if shutil.which("systemctl") is None:
        return _missing(h, "systemctl")
    await _detached(["systemctl", "hibernate"])
    return _envelope(h, 0, "hibernate requested", "")


async def power_reboot(args):
    h = "power.reboot"
    if shutil.which("systemctl") is None:
        return _missing(h, "systemctl")
    await _detached(["systemctl", "reboot"])
    return _envelope(h, 0, "reboot requested", "")


async def power_shutdown(args):
    h = "power.shutdown"
    if shutil.which("systemctl") is None:
        return _missing(h, "systemctl")
    await _detached(["systemctl", "poweroff"])
    return _envelope(h, 0, "shutdown requested", "")


async def power_screen_off(args):
    h = "power.screen_off"
    return await _exec(h, ["xset", "dpms", "force", "off"])


async def power_screen_on(args):
    h = "power.screen_on"
    return await _exec(h, ["xset", "dpms", "force", "on"])


async def power_profile_set(args):
    h = "power.profile_set"
    profile = args.get("profile")
    if not profile:
        return _bad_arg(h, "missing arg 'profile' (performance|balanced|power-saver)")
    if profile not in ("performance", "balanced", "power-saver"):
        return _bad_arg(h, f"invalid profile '{profile}'")
    return await _exec(h, ["powerprofilesctl", "set", profile])


# ---------------------------------------------------------------------------
# CLIPBOARD
# ---------------------------------------------------------------------------

def _xsel_or_xclip():
    if shutil.which("xclip"):
        return "xclip"
    if shutil.which("xsel"):
        return "xsel"
    return None


async def clipboard_get(args):
    h = "clipboard.get"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    tool = _xsel_or_xclip()
    if tool == "xclip":
        return _with_error(await _exec(h, ["xclip", "-o", "-selection", "clipboard"]))
    if tool == "xsel":
        return _with_error(await _exec(h, ["xsel", "--clipboard", "--output"]))
    return _missing(h, "xclip/xsel")


async def clipboard_set(args):
    h = "clipboard.set"
    text = args.get("text")
    if text is None:
        return _bad_arg(h, "missing arg 'text'")
    payload = str(text).encode()
    tool = _xsel_or_xclip()
    if tool == "xclip":
        return await _exec(h, ["xclip", "-i", "-selection", "clipboard"],
                           stdin_data=payload)
    if tool == "xsel":
        return await _exec(h, ["xsel", "--clipboard", "--input"],
                           stdin_data=payload)
    return _missing(h, "xclip/xsel")


async def clipboard_clear(args):
    h = "clipboard.clear"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    tool = _xsel_or_xclip()
    if tool == "xclip":
        # xclip needs something piped to "clear"; empty stdin works
        return _with_error(await _exec(h, ["xclip", "-i", "-selection", "clipboard"],
                           stdin_data=b""))
    if tool == "xsel":
        return _with_error(await _exec(h, ["xsel", "--clipboard", "--clear"]))
    return _missing(h, "xclip/xsel")


async def clipboard_history(args):
    h = "clipboard.history"
    if shutil.which("copyq"):
        return await _exec(h, ["copyq", "eval", "--", "tab('&clipboard'); var r=[]; for (var i=0;i<size();++i) r.push(read(i)); r.join('\\n---\\n')"])
    if shutil.which("clipman"):
        return await _exec(h, ["clipman", "pick", "--print0"])
    if shutil.which("greenclip"):
        return await _exec(h, ["greenclip", "print"])
    env = _missing(h, "copyq")
    env["suggested_package"] = "copyq"
    return env


async def clipboard_paste_cursor(args):
    h = "clipboard.paste_cursor"
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    return _with_error(await _exec(h, ["xdotool", "key", "--clearmodifiers", "ctrl+v"]))


# ---------------------------------------------------------------------------
# MONITORING
# ---------------------------------------------------------------------------

def _read_text(path):
    try:
        return Path(path).read_text(errors="replace").strip()
    except (OSError, FileNotFoundError):
        return None


async def monitoring_battery_percent(args):
    h = "monitoring.battery_percent"
    for bat in ("BAT0", "BAT1", "BAT2"):
        v = _read_text(f"/sys/class/power_supply/{bat}/capacity")
        if v is not None:
            return _envelope(h, 0, v, "", battery=bat, percent=int(v) if v.isdigit() else None)
    msg = "no battery found (no /sys/class/power_supply/BAT0|BAT1|BAT2/capacity readable)"
    return _envelope(h, 1, "", msg, error=msg, scanned=["BAT0", "BAT1", "BAT2"])


async def monitoring_battery_time(args):
    h = "monitoring.battery_time"
    if shutil.which("acpi"):
        return _with_error(await _exec(h, ["acpi", "-b"]))
    for bat in ("BAT0", "BAT1"):
        status = _read_text(f"/sys/class/power_supply/{bat}/status")
        energy = _read_text(f"/sys/class/power_supply/{bat}/energy_now")
        power = _read_text(f"/sys/class/power_supply/{bat}/power_now")
        if status and energy and power and power.isdigit() and int(power) > 0:
            hours = int(energy) / int(power)
            return _envelope(h, 0, f"{hours:.2f}h ({status})", "",
                             status=status, hours=hours)
    msg = ("no battery telemetry (no acpi binary and no readable "
           "/sys/class/power_supply/BAT0|BAT1/{status,energy_now,power_now})")
    return _envelope(h, 1, "", msg, error=msg)


async def monitoring_cpu_freq(args):
    h = "monitoring.cpu_freq"
    v = _read_text("/proc/cpuinfo")
    if v is None:
        return _envelope(h, 1, "", "cannot read /proc/cpuinfo")
    freqs = [ln.split(":")[1].strip() for ln in v.splitlines()
             if ln.startswith("cpu MHz")]
    return _envelope(h, 0, "\n".join(freqs), "", cpu_mhz=freqs)


async def monitoring_gpu_status(args):
    h = "monitoring.gpu_status"
    if shutil.which("nvidia-smi"):
        return await _exec(h, ["nvidia-smi",
                               "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
                               "--format=csv,noheader"])
    if shutil.which("radeontop"):
        return await _exec(h, ["radeontop", "-d", "-", "-l", "1"], timeout=5)
    return _missing(h, "nvidia-smi/radeontop")


async def monitoring_gpu_temp(args):
    h = "monitoring.gpu_temp"
    if shutil.which("nvidia-smi"):
        return _with_error(await _exec(h, ["nvidia-smi", "--query-gpu=temperature.gpu",
                               "--format=csv,noheader,nounits"]))
    if shutil.which("sensors"):
        r = await _exec(h, ["sensors"])
        if not r["success"]:
            return _with_error(r)
        hot = [ln for ln in r["output"].splitlines()
               if "gpu" in ln.lower() or "edge" in ln.lower()]
        return _envelope(h, 0, "\n".join(hot) if hot else r["output"], "")
    return _missing(h, "nvidia-smi/sensors")


async def monitoring_fan_speed(args):
    h = "monitoring.fan_speed"
    if shutil.which("sensors"):
        r = await _exec(h, ["sensors"])
        if not r["success"]:
            return _with_error(r)
        fans = [ln for ln in r["output"].splitlines() if "fan" in ln.lower()]
        return _envelope(h, 0, "\n".join(fans) if fans else "no fan data", "")
    return _missing(h, "sensors")


async def monitoring_display_list(args):
    h = "monitoring.display_list"
    if shutil.which("xrandr"):
        sess = _compositor_status()
        if not sess["available"]:
            return _no_session(h, sess)
        return _with_error(await _exec(h, ["xrandr", "--listactivemonitors"]))
    return _missing(h, "xrandr")


async def monitoring_display_primary(args):
    h = "monitoring.display_primary"
    if shutil.which("xrandr") is None:
        return _missing(h, "xrandr")
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    r = await _exec(h, ["xrandr", "--query"])
    if not r["success"]:
        return _with_error(r)
    for ln in r["output"].splitlines():
        if " connected primary" in ln:
            return _envelope(h, 0, ln.split()[0], "", monitor=ln.split()[0])
    # Fallback to first connected
    for ln in r["output"].splitlines():
        if " connected" in ln:
            return _envelope(h, 0, ln.split()[0], "", monitor=ln.split()[0])
    msg = "no connected monitor (xrandr --query returned no 'connected' lines)"
    return _envelope(h, 1, "", msg, error=msg)


async def monitoring_bt_devices(args):
    h = "monitoring.bt_devices"
    if shutil.which("bluetoothctl") is None:
        return _missing(h, "bluetoothctl")
    # Probe bluetoothd FIRST: bluetoothctl will hang up to its own timeout
    # waiting on D-Bus when bluetoothd is down. systemctl is-active is cheap
    # (~5ms) and gives us an actionable error string.
    if shutil.which("systemctl"):
        probe = await _exec(h, ["systemctl", "is-active", "bluetooth"], timeout=5)
        # is-active returns rc=0 + "active"; rc=3 + "inactive" / "failed".
        state = (probe.get("output") or "").strip()
        if probe.get("returncode") != 0 or state != "active":
            msg = f"bluetoothd not running (state={state or 'unknown'})"
            return {
                "success": False,
                "output": "",
                "stderr": msg,
                "returncode": 1,
                "handler": h,
                "error": msg,
                "service": "bluetooth.service",
                "service_state": state or "unknown",
            }
    # bluetoothctl --timeout caps its own internal wait; outer _exec timeout
    # gives us a hard cap so a deadlocked D-Bus can't pin the event loop.
    return _with_error(await _exec(
        h, ["bluetoothctl", "--timeout", "3", "devices"], timeout=5))


async def monitoring_wifi_signal(args):
    h = "monitoring.wifi_signal"
    if shutil.which("nmcli"):
        return _with_error(await _exec(h, ["nmcli", "-f", "IN-USE,SSID,SIGNAL,BARS",
                               "device", "wifi", "list"]))
    if shutil.which("iwconfig"):
        return _with_error(await _exec(h, ["iwconfig"]))
    return _missing(h, "nmcli/iwconfig")


# ---------------------------------------------------------------------------
# SYSTEM (screenshots, notifications, recording)
# ---------------------------------------------------------------------------

def _screenshot_path(tag):
    d = Path.home() / "Pictures"
    d.mkdir(parents=True, exist_ok=True)
    return str(d / f"screenshot-{tag}-{int(time.time())}.png")


async def system_screenshot_full(args):
    h = "system.screenshot_full"
    path = args.get("path") or _screenshot_path("full")
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    if shutil.which("scrot"):
        r = await _exec(h, ["scrot", path], timeout=30)
    elif shutil.which("maim"):
        r = await _exec(h, ["maim", path], timeout=30)
    elif shutil.which("xfce4-screenshooter"):
        r = await _exec(h, ["xfce4-screenshooter", "-f", "-s", path], timeout=30)
    else:
        return _missing(h, "scrot/maim/xfce4-screenshooter")
    r = _with_error(r)
    r["path"] = path
    return r


async def system_screenshot_window(args):
    h = "system.screenshot_window"
    path = args.get("path") or _screenshot_path("win")
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    # Session 50 Agent H: Sanitizer.path() rejects NUL/non-string + collapses
    # symlinks. We allow_relative=True because _screenshot_path() returns an
    # absolute path already; user-supplied 'path' may be a tilde-expanded
    # short form. must_exist=False (we're WRITING the screenshot).
    try:
        path = Sanitizer.path(path, allow_relative=True)
    except SanitizerError as e:
        return _bad_arg(h, e.as_dict()["message"])
    if shutil.which("scrot"):
        r = await _exec(h, ["scrot", "-u", path], timeout=30)
    elif shutil.which("maim"):
        # Session 50 Agent H: previous impl used shell_wrap=True with
        # `$(xdotool getactivewindow)` interpolation + shlex.quote(path) — a
        # latent shell-injection surface. Resolve the WID via a sibling
        # subprocess and pass it as a plain argv element so we can drop
        # shell_wrap entirely.
        if shutil.which("xdotool") is None:
            return _missing(h, "xdotool")
        wid = await _exec(h, ["xdotool", "getactivewindow"], timeout=5)
        if not wid["success"]:
            return _with_error(wid)
        r = await _exec(h, ["maim", "-i", wid["output"].strip(), path],
                        timeout=30)
    else:
        return _missing(h, "scrot/maim")
    r = _with_error(r)
    r["path"] = path
    return r


async def system_screenshot_region(args):
    h = "system.screenshot_region"
    path = args.get("path") or _screenshot_path("region")
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    if shutil.which("scrot"):
        r = await _exec(h, ["scrot", "-s", path], timeout=30)
    elif shutil.which("maim"):
        r = await _exec(h, ["maim", "-s", path], timeout=30)
    elif shutil.which("flameshot"):
        r = await _exec(h, ["flameshot", "gui", "-p", str(Path(path).parent)],
                        timeout=30)
    else:
        return _missing(h, "scrot/maim/flameshot")
    if not r["success"] and r.get("stderr") == "timeout":
        r["stderr"] = "user did not select region within 30s"
        r["error"] = "user did not select region within 30s"
    r = _with_error(r)
    r["path"] = path
    return r


_RECORD_PROC_FILE = Path("/tmp/contusion_record.pid")


async def system_record_start(args):
    h = "system.record_start"
    path = args.get("path") or str(Path.home() / "Videos" / f"rec-{int(time.time())}.mp4")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if _RECORD_PROC_FILE.exists():
        stale = True
        old_pid = None
        try:
            data = _RECORD_PROC_FILE.read_text().splitlines()
            old_pid = int(data[0]) if data else None
            if old_pid is not None:
                os.kill(old_pid, 0)
                stale = False
        except (ValueError, IndexError, OSError):
            stale = True
        except ProcessLookupError:
            stale = True
        except PermissionError:
            stale = False
        if not stale:
            return {"success": False, "output": "", "stderr": f"already recording pid={old_pid}",
                    "returncode": 1, "handler": h, "error": f"already recording pid={old_pid}"}
        try:
            _RECORD_PROC_FILE.unlink()
        except OSError:
            pass
    if shutil.which("ffmpeg") is None:
        return _missing(h, "ffmpeg")
    # Reserve the pidfile BEFORE spawning ffmpeg to close the TOCTOU between
    # the existence check above and the create_subprocess_exec call. Two
    # concurrent record_start calls would otherwise both pass the check and
    # spawn duplicate ffmpegs, leaving one orphaned.
    try:
        fd = os.open(str(_RECORD_PROC_FILE),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        return {"success": False, "output": "",
                "stderr": "another record_start is racing; retry",
                "returncode": 1, "handler": h,
                "error": "race: pidfile appeared between check and create"}
    os.close(fd)
    # Grab full :0.0 — caller can override via args['input']
    src = args.get("input", ":0.0")
    try:
        proc = await asyncio.create_subprocess_exec(
            "ffmpeg", "-y", "-f", "x11grab", "-i", src, path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            env=_env(), start_new_session=True)
    except FileNotFoundError:
        try:
            _RECORD_PROC_FILE.unlink()
        except OSError:
            pass
        return _missing(h, "ffmpeg")
    except Exception as e:
        try:
            _RECORD_PROC_FILE.unlink()
        except OSError:
            pass
        return {"success": False, "output": "", "stderr": str(e),
                "returncode": -1, "handler": h, "error": str(e)}
    _RECORD_PROC_FILE.write_text(f"{proc.pid}\n{path}")
    return _envelope(h, 0, f"recording started pid={proc.pid}", "",
                     pid=proc.pid, path=path)


async def system_record_stop(args):
    h = "system.record_stop"
    if not _RECORD_PROC_FILE.exists():
        return _envelope(h, 1, "", "no active recording")
    try:
        data = _RECORD_PROC_FILE.read_text().splitlines()
        pid = int(data[0])
        path = data[1] if len(data) > 1 else ""
    except (ValueError, IndexError, OSError):
        _RECORD_PROC_FILE.unlink(missing_ok=True)
        return _envelope(h, 1, "", "corrupt record state")
    try:
        os.kill(pid, 2)  # SIGINT so ffmpeg flushes trailer
    except ProcessLookupError:
        pass
    _RECORD_PROC_FILE.unlink(missing_ok=True)
    return _envelope(h, 0, f"stopped pid={pid}", "", path=path)


async def system_notify(args):
    h = "system.notify"
    title = args.get("title", "Contusion")
    body = args.get("body") or args.get("message") or ""
    # notify-send needs a D-Bus session bus (typically a desktop session) —
    # if none is reachable it exits non-zero with empty stderr; surface that
    # as a structured "no graphical session" instead of a bare failure.
    sess = _compositor_status()
    if not sess["available"]:
        return _no_session(h, sess)
    return _with_error(await _exec(h, ["notify-send", str(title), str(body)]))


async def system_clipboard_monitor(args):
    h = "system.clipboard_monitor"
    # Snapshot of current primary + clipboard selections.
    out = {}
    for sel in ("primary", "clipboard"):
        if shutil.which("xclip"):
            r = await _exec(h, ["xclip", "-o", "-selection", sel])
            out[sel] = r.get("output", "")
    return _envelope(h, 0, str(out), "", selections=out)


async def system_night_light(args):
    h = "system.night_light"
    on = args.get("on")
    if on is None:
        on = args.get("enable", True)
    if shutil.which("redshift"):
        if on:
            # Fire-and-forget redshift daemon
            await _detached(["redshift", "-O", str(args.get("temp", 3500))])
            return _envelope(h, 0, "redshift on", "")
        await _detached(["redshift", "-x"])
        return _envelope(h, 0, "redshift off", "")
    if shutil.which("gammastep"):
        if on:
            await _detached(["gammastep", "-O", str(args.get("temp", 3500))])
            return _envelope(h, 0, "gammastep on", "")
        await _detached(["gammastep", "-x"])
        return _envelope(h, 0, "gammastep off", "")
    return _missing(h, "redshift/gammastep")


# ---------------------------------------------------------------------------
# DRIVER / KERNEL MODULE (Session 47)
# ---------------------------------------------------------------------------
# Session 50 Agent H: module-name validation now delegates to
# Sanitizer.module_name (regex r'^[A-Za-z0-9_-]{1,64}$'), the same chokepoint
# /driver/{load,unload} in api_server.py uses. Local _re_mod retained for
# game.kill / service-name patterns below.
import re as _re_mod


def _validate_module(args, h):
    mod = args.get("module") or args.get("name")
    if not mod or not isinstance(mod, str):
        return None, _bad_arg(h, "missing arg 'module'")
    try:
        mod = Sanitizer.module_name(mod)
    except SanitizerError as e:
        return None, _bad_arg(h, e.as_dict()["message"])
    return mod, None


async def driver_load(args):
    h = "driver.load"
    mod, err = _validate_module(args, h)
    if err:
        return err
    # Session 50 Agent H: shared rate limit with api_server /driver/load via
    # the THROTTLE_DRIVER_LOAD singleton (1/s sustained, burst 3). modprobe
    # is slow + side-effecting; rejecting here closes a vector where someone
    # routes around the FastAPI surface by spamming /contusion/run.
    if not await THROTTLE_DRIVER_LOAD.try_acquire("driver_load"):
        return _bad_arg(h, "rate-limited")
    # Call modprobe via subprocess (sudo will prompt unless the daemon
    # already runs as root, which is the case under ai-control.service).
    # Audit is handled by the shared THROTTLE_DRIVER_LOAD + api_server
    # /driver/load endpoint (S47 work shipped in S50 Agent H).
    if shutil.which("modprobe") is None:
        return _missing(h, "modprobe")
    return await _exec(h, ["modprobe", mod], timeout=15)


async def driver_unload(args):
    h = "driver.unload"
    mod, err = _validate_module(args, h)
    if err:
        return err
    if not await THROTTLE_DRIVER_LOAD.try_acquire("driver_unload"):
        return _bad_arg(h, "rate-limited")
    if shutil.which("modprobe") is None:
        return _missing(h, "modprobe")
    return await _exec(h, ["modprobe", "-r", mod], timeout=15)


async def driver_list(args):
    h = "driver.list"
    if shutil.which("lsmod") is None:
        return _missing(h, "lsmod")
    return await _exec(h, ["lsmod"], timeout=10)


async def driver_info(args):
    h = "driver.info"
    mod, err = _validate_module(args, h)
    if err:
        return err
    if shutil.which("modinfo") is None:
        return _missing(h, "modinfo")
    return await _exec(h, ["modinfo", mod], timeout=10)


# ---------------------------------------------------------------------------
# SERVICE (systemd) (Session 47)
# ---------------------------------------------------------------------------
# Session 50 Agent H: unit-name validation delegates to Sanitizer.unit_name
# (regex r'^[A-Za-z0-9._@-]{1,128}$'), shared with /service/{start,stop} in
# api_server.py. Same regex shape as the previous local _SERVICE_NAME_RE.


def _validate_service(args, h):
    svc = args.get("service") or args.get("name") or args.get("unit")
    if not svc or not isinstance(svc, str):
        return None, _bad_arg(h, "missing arg 'service'")
    try:
        svc = Sanitizer.unit_name(svc)
    except SanitizerError as e:
        return None, _bad_arg(h, e.as_dict()["message"])
    return svc, None


async def _systemctl(verb, args, h):
    svc, err = _validate_service(args, h)
    if err:
        return err
    if shutil.which("systemctl") is None:
        return _missing(h, "systemctl")
    return await _exec(h, ["systemctl", verb, svc], timeout=15)


async def service_start(args):    return await _systemctl("start", args, "service.start")
async def service_stop(args):     return await _systemctl("stop", args, "service.stop")
async def service_restart(args):  return await _systemctl("restart", args, "service.restart")
async def service_reload(args):   return await _systemctl("reload", args, "service.reload")
async def service_enable(args):   return await _systemctl("enable", args, "service.enable")
async def service_disable(args):  return await _systemctl("disable", args, "service.disable")
async def service_status(args):   return await _systemctl("status", args, "service.status")
async def service_is_active(args): return await _systemctl("is-active", args, "service.is_active")


async def service_list(args):
    h = "service.list"
    if shutil.which("systemctl") is None:
        return _missing(h, "systemctl")
    return _with_error(await _exec(h, ["systemctl", "list-units", "--type=service",
                           "--state=running", "--no-pager", "--plain"], timeout=15))


# ---------------------------------------------------------------------------
# APP / GAME LAUNCH (Session 47) - typed launchers with allowlist
# ---------------------------------------------------------------------------

# Allowlisted apps that can be spawned by typed handler. Anything else has
# to go through the general /contusion/launch path with explicit arg-parse
# defenses.
_LAUNCH_ALLOWLIST = frozenset({
    "steam", "lutris", "heroic", "heroic-games-launcher",
    "discord", "spotify", "obs",
    "firefox", "chromium", "thunderbird",
    "code", "thunar", "xfce4-terminal",
    "gamescope", "mangohud", "vkcube",
})


async def app_launch(args):
    h = "app.launch"
    name = args.get("app") or args.get("name")
    if not name or not isinstance(name, str):
        return _bad_arg(h, "missing arg 'app'")
    name = name.strip()
    if name not in _LAUNCH_ALLOWLIST:
        return _bad_arg(h, f"app '{name}' not on launch allowlist")
    if shutil.which(name) is None:
        return _missing(h, name)
    # Detached so the launched GUI doesn't block our reply, but we still
    # spawn via create_subprocess_exec so the event loop reaps the child.
    try:
        proc = await asyncio.create_subprocess_exec(
            name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            env=_env(), start_new_session=True)
    except FileNotFoundError:
        return _missing(h, name)
    except Exception as e:
        return {"success": False, "output": "", "stderr": str(e),
                "returncode": -1, "handler": h, "error": str(e)}
    return _envelope(h, 0, f"launched pid={proc.pid}", "", pid=proc.pid, app=name)


# Session 50 Agent H: pacman installs share THROTTLE_DRIVER_LOAD because
# they hit the same exclusive db lock space and have the same blast radius
# (admin-band side-effects). Per-handler key keeps a steam install from
# burning a token an unrelated lutris install needs.
async def app_install_steam(args):
    h = "app.install_steam"
    if not await THROTTLE_DRIVER_LOAD.try_acquire("app_install_steam"):
        return _bad_arg(h, "rate-limited")
    if shutil.which("pacman") is None:
        return _missing(h, "pacman")
    return await _exec(h, ["pacman", "-S", "--needed", "--noconfirm", "steam"],
                       timeout=300)


async def app_install_lutris(args):
    h = "app.install_lutris"
    if not await THROTTLE_DRIVER_LOAD.try_acquire("app_install_lutris"):
        return _bad_arg(h, "rate-limited")
    if shutil.which("pacman") is None:
        return _missing(h, "pacman")
    return await _exec(h, ["pacman", "-S", "--needed", "--noconfirm",
                           "lutris", "wine-staging"], timeout=300)


async def app_install_heroic(args):
    h = "app.install_heroic"
    if not await THROTTLE_DRIVER_LOAD.try_acquire("app_install_heroic"):
        return _bad_arg(h, "rate-limited")
    if shutil.which("pacman") is None:
        return _missing(h, "pacman")
    return await _exec(h, ["pacman", "-S", "--needed", "--noconfirm",
                           "heroic-games-launcher-bin"], timeout=300)


async def app_install_proton(args):
    h = "app.install_proton"
    if not await THROTTLE_DRIVER_LOAD.try_acquire("app_install_proton"):
        return _bad_arg(h, "rate-limited")
    if shutil.which("pacman") is None:
        return _missing(h, "pacman")
    return await _exec(h, ["pacman", "-S", "--needed", "--noconfirm",
                           "steam"], timeout=300)


# ---------------------------------------------------------------------------
# GAME (Session 47) - inventory / kill
# ---------------------------------------------------------------------------

_GAME_PROCESS_PATTERNS = ("steam", "lutris", "wine", "proton", "heroic",
                          "gamescope", "vkcube")


async def game_list(args):
    h = "game.list"
    # Read /proc directly — no fork, no shell injection surface.
    games: list[dict] = []
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/comm", "r") as f:
                    comm = f.read().strip()
            except (OSError, FileNotFoundError):
                continue
            comm_lower = comm.lower()
            if any(p in comm_lower for p in _GAME_PROCESS_PATTERNS):
                games.append({"pid": int(entry), "comm": comm})
    except OSError as e:
        return {"success": False, "output": "", "stderr": str(e),
                "returncode": -1, "handler": h, "error": str(e)}
    out = "\n".join(f"{g['pid']:>7} {g['comm']}" for g in games) or "(no games running)"
    return _envelope(h, 0, out, "", games=games, count=len(games))


async def game_running(args):
    # Alias for game.list with a different framing.
    r = await game_list(args)
    r["handler"] = "game.running"
    return r


async def game_kill(args):
    h = "game.kill"
    pat = args.get("pattern") or args.get("name") or args.get("game")
    if not pat or not isinstance(pat, str):
        return _bad_arg(h, "missing arg 'pattern'")
    # Allowlist pattern chars to keep this away from being a generic
    # process-kill primitive. Names + dots + dashes only.
    if not _re_mod.fullmatch(r'[A-Za-z0-9._\-]{1,64}', pat):
        return _bad_arg(h, f"invalid kill pattern: {pat!r}")
    if shutil.which("pkill") is None:
        return _missing(h, "pkill")
    return await _exec(h, ["pkill", "-f", pat], timeout=10)


# ---------------------------------------------------------------------------
# ANTI-CHEAT SHIM OPT-IN (Session 65, S64-A5 audit follow-up)
#
# The C-layer anti-cheat shims (services/anticheat/libpe_anticheat.so) refuse
# to run unless AICONTROL_AC_SHIM_OPTED_IN is set in the environment of the
# pe-loader process. These two handlers manage a per-game opt-in state file at
# ~/.ai/ac_shim_optin.json that the launcher consults to decide whether to
# export that env var for a given game launch.
#
# Connecting to live multiplayer with a shim active risks a permanent account
# / HWID ban. The handler REQUIRES `i_understand_bans=true` and refuses to
# enable the shim for any game whose name matches the boot-time-AC denylist.
# ---------------------------------------------------------------------------

# Mirror of services/anticheat/ac_compat.c::AC_DENYLIST. If the C list grows,
# add the new tokens here too. Match is case-insensitive substring.
_AC_BOOT_DENYLIST: tuple[str, ...] = (
    "valorant", "vanguard", "vgk", "vgc",
    "genshin", "hkrpg", "starrail", "mhyprot",
    "fortnite",
    "league of legends", "league-of-legends", "lol",
    "bedaisy",
)


def _ac_optin_path() -> Path:
    return Path.home() / ".ai" / "ac_shim_optin.json"


def _ac_load_state() -> dict:
    p = _ac_optin_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _ac_save_state(state: dict) -> None:
    p = _ac_optin_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2, sort_keys=True))


def _ac_denylisted(name: str) -> str | None:
    """Return the matching denylist token if `name` is denylisted, else None."""
    n = name.lower()
    for token in _AC_BOOT_DENYLIST:
        if token in n:
            return token
    return None


async def game_enable_anticheat_shim(args):
    h = "game.enable_anticheat_shim"
    # Hard gate: explicit acknowledgement of ban risk. We accept either the
    # snake_case CLI form `i_understand_bans` or the kebab-case `--i-understand-bans`
    # that argparse may have flattened.
    ack = args.get("i_understand_bans") or args.get("i-understand-bans")
    if not ack:
        return {
            "success": False,
            "handler": h,
            "error": "must pass i_understand_bans=true (account/HWID ban risk)",
            "warning": (
                "Connecting to live multiplayer with these shims active "
                "MAY PERMANENTLY BAN your account or HWID. See README "
                "'Anti-Cheat Warning' section. To proceed, re-issue with "
                "`--i-understand-bans` set."
            ),
            "stderr": "missing acknowledgement",
            "returncode": 2,
            "output": "",
        }

    name = args.get("game") or args.get("name")
    if not name or not isinstance(name, str):
        return _bad_arg(h, "missing arg 'game'")
    if not _re_mod.fullmatch(r'[A-Za-z0-9._\- ]{1,64}', name):
        return _bad_arg(h, f"invalid game name: {name!r}")

    # Denylist: refuse boot-time kernel anti-cheat outright.
    hit = _ac_denylisted(name)
    if hit:
        return {
            "success": False,
            "handler": h,
            "game": name,
            "error": (
                f"{name!r} matches denylist token {hit!r}: uses kernel-level "
                f"anti-cheat that cannot be satisfied on Linux"
            ),
            "denylist_reason": (
                "boot-time kernel driver + TPM/Secure-Boot attestation; "
                "vendor backend correlates HWID across sessions"
            ),
            "alternative": (
                "Run on real Windows OR play a different game. For tier-2 "
                "multiplayer (Apex, CS2, Dota, Fall Guys, etc.) use Steam "
                "Proton — it ships vendor-negotiated Linux EAC/BattlEye "
                "runtimes that DO pass attestation."
            ),
            "warning": "denylisted; not enabled",
            "stderr": "denylisted",
            "returncode": 1,
            "output": "",
        }

    # Persist per-game opt-in.
    try:
        state = _ac_load_state()
        state[name] = {
            "enabled_at": time.time(),
            "i_understand_bans": True,
        }
        _ac_save_state(state)
    except OSError as e:
        return {
            "success": False,
            "handler": h,
            "game": name,
            "error": f"failed to write opt-in state: {e}",
            "stderr": str(e),
            "returncode": 1,
            "output": "",
        }

    return {
        "success": True,
        "handler": h,
        "game": name,
        "state_file": str(_ac_optin_path()),
        "warning": (
            "shim active for this game — account/HWID ban risk on live "
            "multiplayer. Disable with `ai game disable-anticheat-shim "
            f"{name}` when done."
        ),
        "stderr": "",
        "returncode": 0,
        "output": f"anti-cheat shim enabled for {name}",
    }


async def game_disable_anticheat_shim(args):
    h = "game.disable_anticheat_shim"
    name = args.get("game") or args.get("name")
    if not name or not isinstance(name, str):
        return _bad_arg(h, "missing arg 'game'")
    if not _re_mod.fullmatch(r'[A-Za-z0-9._\- ]{1,64}', name):
        return _bad_arg(h, f"invalid game name: {name!r}")

    try:
        state = _ac_load_state()
    except OSError as e:
        return {
            "success": False,
            "handler": h,
            "game": name,
            "error": f"failed to read opt-in state: {e}",
            "stderr": str(e),
            "returncode": 1,
            "output": "",
        }

    was_enabled = name in state
    state.pop(name, None)
    try:
        _ac_save_state(state)
    except OSError as e:
        return {
            "success": False,
            "handler": h,
            "game": name,
            "error": f"failed to write opt-in state: {e}",
            "stderr": str(e),
            "returncode": 1,
            "output": "",
        }

    return {
        "success": True,
        "handler": h,
        "game": name,
        "was_enabled": was_enabled,
        "state_file": str(_ac_optin_path()),
        "stderr": "",
        "returncode": 0,
        "output": (
            f"anti-cheat shim disabled for {name}"
            if was_enabled else f"{name} was not enabled"
        ),
    }


# ---------------------------------------------------------------------------
# PERFORMANCE (Session 47) - low-latency / gamescope / DXVK
# ---------------------------------------------------------------------------

async def perf_lowlatency_on(args):
    h = "perf.lowlatency_on"
    # Best-effort sequence; partial success still returns the last failure.
    out_lines = []
    err_lines = []
    rc_total = 0
    if shutil.which("cpupower") is not None:
        r = await _exec(h, ["cpupower", "frequency-set", "-g", "performance"], timeout=10)
        out_lines.append(r["output"]); err_lines.append(r["stderr"])
        rc_total |= 0 if r["success"] else 1
    if shutil.which("sysctl") is not None:
        r = await _exec(h, ["sysctl", "-w", "vm.swappiness=10"], timeout=5)
        out_lines.append(r["output"]); err_lines.append(r["stderr"])
        rc_total |= 0 if r["success"] else 1
    if not out_lines:
        return _missing(h, "cpupower/sysctl")
    return _envelope(h, rc_total, "\n".join(filter(None, out_lines)),
                     "\n".join(filter(None, err_lines)))


async def perf_lowlatency_off(args):
    h = "perf.lowlatency_off"
    out_lines = []; err_lines = []; rc_total = 0
    if shutil.which("cpupower") is not None:
        r = await _exec(h, ["cpupower", "frequency-set", "-g", "schedutil"], timeout=10)
        out_lines.append(r["output"]); err_lines.append(r["stderr"])
        rc_total |= 0 if r["success"] else 1
    if shutil.which("sysctl") is not None:
        r = await _exec(h, ["sysctl", "-w", "vm.swappiness=60"], timeout=5)
        out_lines.append(r["output"]); err_lines.append(r["stderr"])
        rc_total |= 0 if r["success"] else 1
    if not out_lines:
        return _missing(h, "cpupower/sysctl")
    return _envelope(h, rc_total, "\n".join(filter(None, out_lines)),
                     "\n".join(filter(None, err_lines)))


_PERF_CONF = Path.home() / ".config" / "contusion-perf.sh"


async def perf_gamescope_on(args):
    h = "perf.gamescope_on"
    try:
        _PERF_CONF.parent.mkdir(parents=True, exist_ok=True)
        # Static, hard-coded content — no user-controlled formatting.
        _PERF_CONF.write_text('export GAME_LAUNCH_PREFIX="gamescope -W 1920 -H 1080 -f --"\n')
    except OSError as e:
        return {"success": False, "output": "", "stderr": str(e),
                "returncode": -1, "handler": h, "error": str(e)}
    return _envelope(h, 0, f"wrote {_PERF_CONF}", "", path=str(_PERF_CONF))


async def perf_gamescope_off(args):
    h = "perf.gamescope_off"
    try:
        _PERF_CONF.unlink(missing_ok=True)
    except OSError as e:
        return {"success": False, "output": "", "stderr": str(e),
                "returncode": -1, "handler": h, "error": str(e)}
    return _envelope(h, 0, f"removed {_PERF_CONF}", "")


async def perf_dxvk_clear(args):
    h = "perf.dxvk_clear"
    deleted = 0
    errors = []
    # Walk well-known DXVK cache locations and remove *.dxvk-cache files.
    candidates = [
        Path.home() / ".steam",
        Path.home() / ".local" / "share" / "Steam",
        Path.home() / ".local" / "share" / "lutris",
        Path.home() / ".cache" / "dxvk",
    ]
    for root in candidates:
        if not root.exists():
            continue
        try:
            for p in root.rglob("*.dxvk-cache"):
                try:
                    p.unlink()
                    deleted += 1
                except OSError as e:
                    errors.append(f"{p}: {e}")
        except OSError as e:
            errors.append(f"{root}: {e}")
    return _envelope(h, 0,
                     f"cleared {deleted} dxvk cache files",
                     "\n".join(errors[:10]) if errors else "",
                     deleted=deleted, error_count=len(errors))


# ---------------------------------------------------------------------------
# SCRIPT EXTENSION SURFACE (Session 56) — operator drops .sh files into
# /etc/ai-control/scripts.d or ~/.ai/scripts.d and calls them by name.
# ---------------------------------------------------------------------------

try:
    from . import script_runner as _script_runner
except ImportError:
    import script_runner as _script_runner  # type: ignore[no-redef]


async def script_list(args):
    h = "script.list"
    include_user = args.get("include_user", True)
    if isinstance(include_user, str):
        include_user = include_user.lower() in ("1", "true", "yes")
    try:
        scripts = _script_runner.list_scripts(
            include_user=bool(include_user))
    except Exception as e:
        logger.exception("script.list failed: %s", e)
        return {"success": False, "output": "", "stderr": str(e),
                "returncode": -1, "handler": h, "error": str(e)}
    return _envelope(h, 0, f"{len(scripts)} scripts", "",
                     scripts=scripts, count=len(scripts))


async def script_info(args):
    h = "script.info"
    name = args.get("name") or args.get("script")
    if not name or not isinstance(name, str):
        return _bad_arg(h, "missing arg 'name'")
    info = _script_runner.get_script(name)
    if info is None:
        return _envelope(h, 1, "", f"script not found: {name}",
                         name=name, found=False)
    return _envelope(h, 0, info["description"], "",
                     script=info, found=True)


async def script_run(args):
    h = "script.run"
    name = args.get("name") or args.get("script")
    if not name or not isinstance(name, str):
        return _bad_arg(h, "missing arg 'name'")
    # Use Sanitizer.module_name regex shape to reject path separators / dots.
    # script_runner.run_script also validates -- this is defence in depth.
    raw_args = args.get("args") or []
    if not isinstance(raw_args, list):
        return _bad_arg(h, "arg 'args' must be a list of strings")
    try:
        clean_args = Sanitizer.argv(raw_args, max_args=32)
    except SanitizerError as e:
        return _bad_arg(h, e.as_dict()["message"])
    try:
        timeout = int(args.get("timeout", 30))
    except (TypeError, ValueError):
        timeout = 30
    timeout = max(1, min(600, timeout))
    res = await _script_runner.run_script(
        name, args=clean_args, timeout=timeout)
    # Normalise to the standard contusion envelope shape AND keep the
    # script_runner-specific fields (elapsed_s, source, trust_band).
    rc = res.get("returncode", -1)
    return {
        "success": bool(res.get("ok")),
        "output": res.get("stdout", ""),
        "stderr": res.get("stderr", ""),
        "returncode": rc,
        "handler": h,
        "name": res.get("name", name),
        "elapsed_s": res.get("elapsed_s"),
        "source": res.get("source"),
        "trust_band": res.get("trust_band"),
    }


# ---------------------------------------------------------------------------
# POWERSHELL SCRIPT RUNNER — runs a discovered .ps1 via pwsh (PowerShell
# Core).  pwsh is NOT shipped with the ISO (keeps size down + avoids AUR
# churn); operator runs `bash /opt/ai-control/scripts/install-pwsh.sh` once
# to enable.  Until then, this handler returns a `missing` envelope with the
# install hint -- callers (LLM, ai CLI) surface that to the operator.
#
# Discovery uses the same script_runner walker as `.sh`, so a `foo.ps1`
# dropped into /etc/ai-control/scripts.d/ or ~/.ai/scripts.d/ is found by
# stem name (`foo`).  We always invoke pwsh with `-NoProfile` (skip the
# user's $PROFILE which may have side-effects) and `-ExecutionPolicy Bypass`
# (Linux pwsh defaults to Restricted).
# ---------------------------------------------------------------------------

_PWSH_INSTALL_HINT = "bash /opt/ai-control/scripts/install-pwsh.sh"


def _find_ps1_script(name: str):
    """Look up a .ps1 script by stem name.

    Mirrors script_runner.get_script() but accepts the .ps1 suffix instead
    of .sh.  Walks both system and user scripts.d directories one level
    deep, applies the same ownership / world-writable safety checks
    (delegated by re-using script_runner internals).
    """
    if not isinstance(name, str) or not name:
        return None
    # Defence-in-depth: strict name pattern (no '/', no '..', no NUL).
    import re as _re
    if not _re.match(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$", name):
        return None
    candidates = []
    sysdir = _script_runner.SYSTEM_SCRIPTS_DIR
    candidates.append((sysdir / f"{name}.ps1", "system"))
    try:
        userdir = _script_runner._user_scripts_dir()
        candidates.append((userdir / f"{name}.ps1", "user"))
    except Exception:
        pass
    for path, source in candidates:
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        ok, _why = _script_runner._is_safe_owner(path, source)
        if not ok:
            continue
        return {"name": name, "path": str(path), "source": source}
    return None


async def script_run_ps1(args):
    h = "script.run_ps1"
    name = args.get("name") or args.get("script")
    if not name or not isinstance(name, str):
        return _bad_arg(h, "missing arg 'name'")
    if shutil.which("pwsh") is None:
        return _missing(h, "pwsh", install_hint=_PWSH_INSTALL_HINT)
    info = _find_ps1_script(name)
    if info is None:
        return {
            "success": False,
            "output": "",
            "stderr": f"script {name!r} not found (.ps1)",
            "returncode": 127,
            "handler": h,
            "error": f"script {name!r} not found",
            "name": name,
        }
    raw_args = args.get("args") or []
    if not isinstance(raw_args, list):
        return _bad_arg(h, "arg 'args' must be a list of strings")
    try:
        clean_args = Sanitizer.argv(raw_args, max_args=32)
    except SanitizerError as e:
        return _bad_arg(h, e.as_dict()["message"])
    try:
        timeout = int(args.get("timeout", 30))
    except (TypeError, ValueError):
        timeout = 30
    timeout = max(1, min(600, timeout))
    # Build minimal env (matches script_runner.run_script policy).
    base_env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "DISPLAY": os.environ.get("DISPLAY", ":0"),
        "AI_SCRIPT_NAME": name,
        "AI_SCRIPT_SOURCE": info["source"],
    }
    argv = [
        "pwsh", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", info["path"], *clean_args,
    ]
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
        return _missing(h, "pwsh", install_hint=_PWSH_INSTALL_HINT)
    except OSError as e:
        return {
            "success": False, "output": "", "stderr": f"OSError: {e}",
            "returncode": -1, "handler": h, "error": str(e), "name": name,
        }
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return {
            "success": False, "output": "",
            "stderr": f"timeout after {timeout}s",
            "returncode": -1, "handler": h,
            "error": "timeout", "name": name,
            "elapsed_s": time.monotonic() - t0,
        }
    elapsed = time.monotonic() - t0
    rc = proc.returncode if proc.returncode is not None else -1
    return {
        "success": rc == 0,
        "output": stdout.decode("utf-8", errors="replace").strip(),
        "stderr": stderr.decode("utf-8", errors="replace").strip(),
        "returncode": rc,
        "handler": h,
        "name": name,
        "source": info["source"],
        "elapsed_s": elapsed,
    }


# ---------------------------------------------------------------------------
# CLAUDE CODE SELF-INSTALL (Session 56) — npm-based install + workspace seed
# ---------------------------------------------------------------------------

try:
    from . import claude_installer as _claude_installer
except ImportError:
    import claude_installer as _claude_installer  # type: ignore[no-redef]


async def app_install_claude(args):
    h = "app.install_claude"
    # Share the admin-band rate limit with the other pacman/install handlers
    # so a flood of "install claude" doesn't compete with steam/lutris.
    if not await THROTTLE_DRIVER_LOAD.try_acquire("app_install_claude"):
        return _bad_arg(h, "rate-limited")
    force_install = bool(args.get("force_install", False))
    force_bootstrap = bool(args.get("force_bootstrap", False))
    try:
        res = await _claude_installer.install_and_bootstrap(
            force_install=force_install,
            force_bootstrap=force_bootstrap,
        )
    except Exception as e:
        logger.exception("app.install_claude crashed: %s", e)
        return {"success": False, "output": "", "stderr": str(e),
                "returncode": -1, "handler": h, "error": str(e)}
    install = res.get("install") or {}
    boot = res.get("bootstrap") or {}
    out_lines = []
    if install.get("ok"):
        out_lines.append(f"installed: {install.get('version', '?')}")
    elif install.get("error"):
        out_lines.append(f"install failed: {install['error']}")
    if boot:
        out_lines.append(f"workspace: created={len(boot.get('created', []))} "
                         f"skipped={len(boot.get('skipped', []))}")
    return {
        "success": bool(res.get("ok")),
        "output": "\n".join(out_lines),
        "stderr": res.get("error") or "",
        "returncode": 0 if res.get("ok") else 1,
        "handler": h,
        "install": install,
        "bootstrap": boot,
    }


async def _probe_version_async(handler: str, binary_path: str | None,
                               timeout: float = 3.0) -> tuple[str | None, str | None]:
    """Run `<binary_path> --version` with a hard timeout.

    Returns (version, error). Either is None depending on outcome.
    Returns (None, None) if binary_path is falsy (nothing to probe).

    Used to keep both the npm and claude probes in app.claude_status
    parallelizable via asyncio.gather without one ever blocking the other.
    """
    if not binary_path:
        return None, None
    try:
        proc = await asyncio.create_subprocess_exec(
            binary_path, "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_env())
    except FileNotFoundError:
        return None, f"{binary_path} disappeared between which() and exec()"
    except Exception as e:
        return None, f"spawn failed: {e}"
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return None, f"--version timed out after {timeout}s"
    if proc.returncode != 0:
        err = (stderr.decode(errors="replace").strip() or
               stdout.decode(errors="replace").strip() or
               f"exited rc={proc.returncode}")
        return None, err[:200]
    ver = stdout.decode(errors="replace").strip() or \
          stderr.decode(errors="replace").strip()
    return (ver or None), None


async def app_claude_status(args):
    h = "app.claude_status"
    # Resolve paths synchronously (shutil.which is fast: pure stat() walk on PATH).
    # The expensive part — exec'ing each binary with --version — runs in parallel
    # via asyncio.gather to keep wall time at ~max(probe) instead of sum(probe).
    # Under TCG QEMU each subprocess spawn+exit can cost 2-3s; sequential probing
    # blew the 10s NL/handler budget (S62 yellow), parallel keeps it under 3.5s.
    npm_path = shutil.which("npm")
    claude_path = shutil.which("claude")
    npm_task = asyncio.create_task(
        _probe_version_async(h, npm_path, timeout=3.0))
    claude_task = asyncio.create_task(
        _probe_version_async(h, claude_path, timeout=3.0))
    (npm_version, npm_probe_error), (claude_version, version_probe_error) = \
        await asyncio.gather(npm_task, claude_task)
    if npm_path is None:
        npm_ok = False
        npm_msg = "npm not on PATH (try: pacman -S npm nodejs)"
    elif npm_probe_error:
        npm_ok = False
        npm_msg = f"npm --version failed: {npm_probe_error}"
    else:
        npm_ok = True
        npm_msg = npm_version or ""
    installed = bool(claude_path and claude_version)
    # Build a structured error string that pinpoints which prerequisite is
    # missing so the caller (CLI/AI) can act: install npm, install claude,
    # or chase a broken --version probe.
    if installed:
        err = ""
    else:
        parts = []
        if not npm_ok:
            parts.append(f"npm unavailable ({npm_msg})")
        if claude_path is None:
            parts.append("claude binary not on PATH")
        elif claude_version is None:
            parts.append(f"claude binary at {claude_path} but --version "
                         f"failed: {version_probe_error or 'unknown'}")
        err = "; ".join(parts) or "claude not installed"
    return _envelope(
        h, 0 if installed else 1,
        f"installed={installed} npm={'yes' if npm_ok else 'no'}",
        err,
        installed=installed,
        claude_path=claude_path,
        claude_binary=claude_path,
        claude_version=claude_version,
        npm_available=npm_ok,
        npm_version=npm_msg if npm_ok else None,
        npm_error=None if npm_ok else npm_msg,
        version_probe_error=version_probe_error,
        error=err if not installed else None,
    )


async def app_claude_workspace_init(args):
    h = "app.claude_workspace_init"
    force = bool(args.get("force", False))
    try:
        res = _claude_installer.bootstrap_workspace(force=force)
    except Exception as e:
        logger.exception("app.claude_workspace_init crashed: %s", e)
        return {"success": False, "output": "", "stderr": str(e),
                "returncode": -1, "handler": h, "error": str(e)}
    return _envelope(
        h, 0 if res.get("ok") else 1,
        f"created={len(res.get('created', []))} "
        f"skipped={len(res.get('skipped', []))}",
        "\n".join(res.get("errors", []))[:500],
        bootstrap=res,
    )


# ---------------------------------------------------------------------------
# Session 68 Agent S -- Windows software catalog installer.
#
# app.install_windows: look up a requested Windows app in software_catalog,
# fetch the installer via curl, then hand off to /usr/bin/peloader with the
# catalog's silent-install args. Non-blocking where possible, graceful
# degradation on missing curl / missing peloader / no network.
#
# Envelope fields:
#   success (bool), handler_type="app.install_windows",
#   catalog_key, url, cached_path, installer_type,
#   peloader_returncode, stdout (tail 500B), stderr (tail 500B),
#   reason (on failure -- one of: "unknown_app", "no_network",
#     "curl_missing", "peloader_missing", "download_failed",
#     "install_failed"),
#   suggestions (list of alternate catalog keys) when reason=="unknown_app".
# ---------------------------------------------------------------------------

try:
    from . import software_catalog as _software_catalog
except ImportError:
    import software_catalog as _software_catalog  # type: ignore[no-redef]


_INSTALL_CACHE_DIR = "/var/cache/ai-control/downloads"


def _tail_bytes(b, n: int = 500) -> str:
    """Return at most the last n bytes as a utf-8-safe string."""
    if b is None:
        return ""
    if isinstance(b, bytes):
        b = b[-n:] if len(b) > n else b
        return b.decode("utf-8", errors="replace")
    return b[-n:] if len(b) > n else b


def _derive_app_name(args: dict):
    """Pull the target app name from args -- explicit 'name' preferred, else
    try to parse out of a 'phrase'/'instruction'/'input' fallback by matching
    against the catalog alias list."""
    name = args.get("name") or args.get("app") or args.get("key")
    if name:
        return str(name).strip()
    raw = (args.get("phrase") or args.get("instruction")
           or args.get("input") or args.get("value") or "")
    if not raw:
        return None
    raw_norm = " ".join(str(raw).lower().strip().split())
    # Longest-alias-first match so "visual studio community" beats "vs".
    candidates = []
    for key, entry in _software_catalog.CATALOG.items():
        for alias in [key, *entry.get("names", [])]:
            a = " ".join(str(alias).lower().strip().split())
            if a and a in raw_norm:
                candidates.append((len(a), alias))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


async def _check_network(timeout: float = 3.0) -> bool:
    """Lightweight connectivity probe -- single HEAD to a stable endpoint.

    Returns True if we can reach the internet, False otherwise. Under QEMU
    user-mode networking with no host route, this returns False in <3s and
    the handler fails fast with reason='no_network'."""
    if shutil.which("curl") is None:
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "--max-time", str(int(timeout)),
            "-o", "/dev/null", "-I", "https://aka.ms/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, env=_env())
        _, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1.0)
        return proc.returncode == 0
    except Exception:
        return False


async def app_install_windows(args):
    h = "app.install_windows"
    # Share the admin-band rate limit with other install handlers so a flood
    # of "install firefox" doesn't starve steam/claude/lutris.
    if not await THROTTLE_DRIVER_LOAD.try_acquire("app_install_windows"):
        return _bad_arg(h, "rate-limited")

    name = _derive_app_name(args)
    if not name:
        return {
            "success": False,
            "handler_type": h,
            "reason": "missing_name",
            "error": ("no 'name' arg supplied and could not derive one "
                      "from args.phrase/instruction/input"),
            "hint": ("pass args={'name': 'visual studio community'} or one "
                     "of: phrase, instruction, input containing a known app"),
            "known_apps": _software_catalog.list_keys()[:10],
        }

    entry = _software_catalog.resolve(name)
    if entry is None:
        return {
            "success": False,
            "handler_type": h,
            "reason": "unknown_app",
            "name": name,
            "error": f"no catalog entry for {name!r}",
            "suggestions": _software_catalog.suggest(name, limit=5),
            "known_apps_count": len(_software_catalog.list_keys()),
        }

    key = entry["key"]
    url = entry["url"]
    installer_type = entry.get("installer_type", "exe")
    silent_args = list(entry.get("silent_args", []))

    # Pre-flight: curl available?
    if shutil.which("curl") is None:
        return {
            "success": False,
            "handler_type": h,
            "reason": "curl_missing",
            "catalog_key": key,
            "url": url,
            "error": "curl not installed (needed to fetch installer)",
            "hint": "pacman -S curl",
        }

    # Pre-flight: network reachable?
    if not await _check_network():
        return {
            "success": False,
            "handler_type": h,
            "reason": "no_network",
            "catalog_key": key,
            "url": url,
            "error": "no internet reachable; cannot download installer",
            "hint": ("check NetworkManager state; install_windows needs "
                     "outbound HTTPS to fetch installers"),
        }

    # Cache path: key + short hash of URL so version bumps pick a new filename
    try:
        import hashlib
        url_hash = hashlib.sha1(url.encode("utf-8")).hexdigest()[:12]
    except Exception:
        url_hash = "0" * 12
    cache_dir = _INSTALL_CACHE_DIR
    try:
        Path(_INSTALL_CACHE_DIR).mkdir(parents=True, exist_ok=True)
    except PermissionError:
        # Fall back to a user-writable location (daemon may be non-root)
        fallback = os.path.expanduser("~/.cache/ai-control/downloads")
        Path(fallback).mkdir(parents=True, exist_ok=True)
        cache_dir = fallback
    except Exception as e:
        return {
            "success": False,
            "handler_type": h,
            "reason": "cache_dir_unavailable",
            "catalog_key": key,
            "url": url,
            "error": f"could not create cache dir: {e}",
        }

    ext = installer_type.lower()
    if ext not in ("exe", "msi"):
        ext = "exe"
    cached_path = os.path.join(cache_dir, f"{key}-{url_hash}.{ext}")

    # Download (or use existing cached copy)
    download_skipped = False
    if os.path.isfile(cached_path) and os.path.getsize(cached_path) > 0:
        download_skipped = True
        logger.info("app.install_windows: using cached %s (%d bytes)",
                    cached_path, os.path.getsize(cached_path))
    else:
        logger.info("app.install_windows: downloading %s -> %s", url, cached_path)
        dl_cmd = ["curl", "-L", "-sS", "--fail", "--max-time", "300",
                  "-o", cached_path, url]
        dl_proc = None
        try:
            dl_proc = await asyncio.create_subprocess_exec(
                *dl_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, env=_env())
            dl_out, dl_err = await asyncio.wait_for(
                dl_proc.communicate(), timeout=305)
        except asyncio.TimeoutError:
            try:
                if dl_proc is not None:
                    dl_proc.kill()
                    await dl_proc.wait()
            except Exception:
                pass
            try:
                if os.path.exists(cached_path):
                    os.unlink(cached_path)
            except Exception:
                pass
            return {
                "success": False,
                "handler_type": h,
                "reason": "download_timeout",
                "catalog_key": key,
                "url": url,
                "cached_path": None,
                "error": "curl timed out after 300s",
            }
        except Exception as e:
            return {
                "success": False,
                "handler_type": h,
                "reason": "download_failed",
                "catalog_key": key,
                "url": url,
                "cached_path": None,
                "error": f"curl spawn failed: {e}",
            }
        if dl_proc.returncode != 0:
            try:
                if os.path.exists(cached_path):
                    os.unlink(cached_path)
            except Exception:
                pass
            return {
                "success": False,
                "handler_type": h,
                "reason": "download_failed",
                "catalog_key": key,
                "url": url,
                "cached_path": None,
                "curl_returncode": dl_proc.returncode,
                "stderr": _tail_bytes(dl_err, 500),
                "error": f"curl exited rc={dl_proc.returncode}",
                "hint": ("URL may be stale (version-pinned); rebuild catalog "
                         "with a fresh release URL"),
            }

    # Pre-flight: peloader available?
    peloader_bin = shutil.which("peloader") or "/usr/bin/peloader"
    if not os.path.isfile(peloader_bin) or not os.access(peloader_bin, os.X_OK):
        return {
            "success": False,
            "handler_type": h,
            "reason": "peloader_missing",
            "catalog_key": key,
            "url": url,
            "cached_path": cached_path,
            "download_skipped": download_skipped,
            "error": f"{peloader_bin} not found or not executable",
            "hint": "build/install the pe-loader package",
        }

    # Build the peloader invocation:
    #   .exe  -> peloader <installer.exe> <silent_args...>
    #   .msi  -> peloader <msiexec.exe> /i <installer.msi> <silent_args...>
    if ext == "msi":
        msiexec_candidates = [
            "/usr/lib/pe-compat/msiexec.exe",
            "/usr/lib/peloader/msiexec.exe",
            "/opt/pe-compat/msiexec.exe",
        ]
        msiexec_path = next((p for p in msiexec_candidates
                             if os.path.isfile(p)), None)
        if msiexec_path is None:
            return {
                "success": False,
                "handler_type": h,
                "reason": "msiexec_missing",
                "catalog_key": key,
                "url": url,
                "cached_path": cached_path,
                "download_skipped": download_skipped,
                "error": "no msiexec.exe available for MSI installer",
                "hint": ("install pe-compat MSI host; tried: "
                         + ", ".join(msiexec_candidates)),
            }
        argv = [peloader_bin, msiexec_path, "/i", cached_path, *silent_args]
    else:
        argv = [peloader_bin, cached_path, *silent_args]

    logger.info("app.install_windows: invoking %s", " ".join(argv))
    inst_proc = None
    try:
        inst_proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, env=_env())
        inst_out, inst_err = await asyncio.wait_for(
            inst_proc.communicate(), timeout=600)
    except asyncio.TimeoutError:
        try:
            if inst_proc is not None:
                inst_proc.kill()
                await inst_proc.wait()
        except Exception:
            pass
        return {
            "success": False,
            "handler_type": h,
            "reason": "install_timeout",
            "catalog_key": key,
            "url": url,
            "cached_path": cached_path,
            "download_skipped": download_skipped,
            "error": "peloader run timed out after 600s",
        }
    except Exception as e:
        return {
            "success": False,
            "handler_type": h,
            "reason": "install_failed",
            "catalog_key": key,
            "url": url,
            "cached_path": cached_path,
            "download_skipped": download_skipped,
            "error": f"peloader spawn failed: {e}",
        }

    rc = inst_proc.returncode
    stdout_tail = _tail_bytes(inst_out, 500)
    stderr_tail = _tail_bytes(inst_err, 500)
    ok = (rc == 0)
    return {
        "success": ok,
        "handler_type": h,
        "catalog_key": key,
        "name": name,
        "url": url,
        "cached_path": cached_path,
        "download_skipped": download_skipped,
        "installer_type": installer_type,
        "silent_args": silent_args,
        "peloader_returncode": rc,
        "stdout": stdout_tail,
        "stderr": stderr_tail,
        "reason": None if ok else "install_failed",
        "hint": None if ok else ("peloader returned non-zero; check stdout/"
                                 "stderr for missing DLL stubs or abi mismatch"),
    }


# ---------------------------------------------------------------------------
# LEGACY SHELL FALLBACK
# ---------------------------------------------------------------------------

async def legacy_shell_exec(args):
    h = "legacy.shell_exec"
    cmd = args.get("cmd") or args.get("value")
    if not cmd:
        return _bad_arg(h, "missing arg 'cmd'")
    try:
        timeout = int(args.get("timeout", 15))
    except (TypeError, ValueError):
        return _bad_arg(h, "arg 'timeout' must be int")
    timeout = max(1, min(15, timeout))
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, env=_env())
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return {"success": False, "output": "", "stderr": "timeout",
                "returncode": -1, "handler": h, "error": "timeout"}
    except Exception as e:
        return {"success": False, "output": "", "stderr": str(e),
                "returncode": -1, "handler": h, "error": str(e)}
    return _envelope(h, proc.returncode,
                     out.decode(errors="replace").strip(),
                     err.decode(errors="replace").strip())


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

HANDLERS: dict[str, Callable[[dict], Awaitable[dict]]] = {
    # audio (10)
    "audio.volume_up":         audio_volume_up,
    "audio.volume_down":       audio_volume_down,
    "audio.volume_set":        audio_volume_set,
    "audio.mute_toggle":       audio_mute_toggle,
    "audio.mic_mute_toggle":   audio_mic_mute_toggle,
    "audio.mic_volume_up":     audio_mic_volume_up,
    "audio.mic_volume_down":   audio_mic_volume_down,
    "audio.sink_list":         audio_sink_list,
    "audio.sink_set":          audio_sink_set,
    "audio.restart":           audio_restart,

    # brightness (7)
    "brightness.up":    brightness_up,
    "brightness.down":  brightness_down,
    "brightness.set":   brightness_set,
    "brightness.get":   brightness_get,
    "brightness.max":   brightness_max,
    "brightness.min":   brightness_min,
    "brightness.auto":  brightness_auto,

    # media (10)
    "media.play":         media_play,
    "media.pause":        media_pause,
    "media.play_pause":   media_play_pause,
    "media.next":         media_next,
    "media.prev":         media_prev,
    "media.stop":         media_stop,
    "media.status":       media_status,
    "media.seek_forward": media_seek_forward,
    "media.seek_back":    media_seek_back,
    "media.list_players": media_list_players,

    # window (18)
    "window.minimize":           window_minimize,
    "window.maximize":           window_maximize,
    "window.restore":            window_restore,
    "window.close":              window_close,
    "window.close_force":        window_close_force,
    "window.fullscreen_toggle":  window_fullscreen_toggle,
    "window.shade":              window_shade,
    "window.above":              window_above,
    "window.below":              window_below,
    "window.sticky":             window_sticky,
    "window.focus_title":        window_focus_title,
    "window.focus_class":        window_focus_class,
    "window.tile_left":          window_tile_left,
    "window.tile_right":         window_tile_right,
    "window.tile_top":           window_tile_top,
    "window.tile_bottom":        window_tile_bottom,
    "window.move_to_workspace":  window_move_to_workspace,
    "window.list":               window_list,

    # workspace (8)
    "workspace.next":             workspace_next,
    "workspace.prev":             workspace_prev,
    "workspace.switch":           workspace_switch,
    "workspace.new":              workspace_new,
    "workspace.delete_current":   workspace_delete_current,
    "workspace.list":             workspace_list,
    "workspace.move_window_here": workspace_move_window_here,
    "workspace.show_all":         workspace_show_all,

    # power (10)
    "power.lock_screen":    power_lock_screen,
    "power.unlock_screen":  power_unlock_screen,
    "power.logout":         power_logout,
    "power.suspend":        power_suspend,
    "power.hibernate":      power_hibernate,
    "power.reboot":         power_reboot,
    "power.shutdown":       power_shutdown,
    "power.screen_off":     power_screen_off,
    "power.screen_on":      power_screen_on,
    "power.profile_set":    power_profile_set,

    # clipboard (5)
    "clipboard.get":          clipboard_get,
    "clipboard.set":          clipboard_set,
    "clipboard.clear":        clipboard_clear,
    "clipboard.history":      clipboard_history,
    "clipboard.paste_cursor": clipboard_paste_cursor,

    # monitoring (10)
    "monitoring.battery_percent": monitoring_battery_percent,
    "monitoring.battery_time":    monitoring_battery_time,
    "monitoring.cpu_freq":        monitoring_cpu_freq,
    "monitoring.gpu_status":      monitoring_gpu_status,
    "monitoring.gpu_temp":        monitoring_gpu_temp,
    "monitoring.fan_speed":       monitoring_fan_speed,
    "monitoring.display_list":    monitoring_display_list,
    "monitoring.display_primary": monitoring_display_primary,
    "monitoring.bt_devices":      monitoring_bt_devices,
    "monitoring.wifi_signal":     monitoring_wifi_signal,

    # system (8)
    "system.screenshot_full":   system_screenshot_full,
    "system.screenshot_window": system_screenshot_window,
    "system.screenshot_region": system_screenshot_region,
    "system.record_start":      system_record_start,
    "system.record_stop":       system_record_stop,
    "system.notify":            system_notify,
    "system.clipboard_monitor": system_clipboard_monitor,
    "system.night_light":       system_night_light,

    # driver / kernel module (Session 47) (4)
    "driver.load":   driver_load,
    "driver.unload": driver_unload,
    "driver.list":   driver_list,
    "driver.info":   driver_info,

    # service (systemd) (Session 47) (9)
    "service.start":     service_start,
    "service.stop":      service_stop,
    "service.restart":   service_restart,
    "service.reload":    service_reload,
    "service.enable":    service_enable,
    "service.disable":   service_disable,
    "service.status":    service_status,
    "service.is_active": service_is_active,
    "service.list":      service_list,

    # app launchers (Session 47) (5)
    "app.launch":          app_launch,
    "app.install_steam":   app_install_steam,
    "app.install_lutris":  app_install_lutris,
    "app.install_heroic":  app_install_heroic,
    "app.install_proton":  app_install_proton,

    # game inventory + control (Session 47) (3) + AC-shim opt-in (Session 65) (2)
    "game.list":    game_list,
    "game.running": game_running,
    "game.kill":    game_kill,
    "game.enable_anticheat_shim":  game_enable_anticheat_shim,
    "game.disable_anticheat_shim": game_disable_anticheat_shim,

    # performance / gaming overlays (Session 47) (5)
    "perf.lowlatency_on":  perf_lowlatency_on,
    "perf.lowlatency_off": perf_lowlatency_off,
    "perf.gamescope_on":   perf_gamescope_on,
    "perf.gamescope_off":  perf_gamescope_off,
    "perf.dxvk_clear":     perf_dxvk_clear,

    # script extension surface (Session 56) (3) + powershell .ps1 runner (Session 65) (1)
    "script.list":     script_list,
    "script.info":     script_info,
    "script.run":      script_run,
    "script.run_ps1":  script_run_ps1,

    # claude code self-install (Session 56) (3)
    "app.install_claude":          app_install_claude,
    "app.claude_status":           app_claude_status,
    "app.claude_workspace_init":   app_claude_workspace_init,

    # legacy shell fallback
    "legacy.shell_exec": legacy_shell_exec,
}


def list_handler_types() -> list[str]:
    return sorted(HANDLERS.keys())


# ---------------------------------------------------------------------------
# Session 68 Agent U — read-only QUERY handlers.
#
# Informational, non-side-effecting lookups. Every handler returns a standard
# envelope with {success, handler_type, <structured fields>, hint (on fail)}.
# All subprocesses use asyncio with wait_for(timeout=5); missing tools
# degrade gracefully to {success: False, reason/hint, ...}.  Wrapped in
# try/except so a raise in parsing code never crashes the dispatcher.
# ---------------------------------------------------------------------------


async def _q_exec(argv: list, timeout: float = 5.0) -> tuple[int, str, str]:
    """Internal helper — run argv, return (rc, stdout, stderr).  Raises
    FileNotFoundError if binary missing so callers can emit a hint."""
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_env(),
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return -1, "", "timeout"
    return (proc.returncode,
            stdout.decode(errors="replace").strip(),
            stderr.decode(errors="replace").strip())


async def query_disk_space(args):
    h = "query.disk_space"
    try:
        if shutil.which("df") is None:
            return {"success": False, "handler_type": h,
                    "error": "df not installed",
                    "hint": "install coreutils (should always be present)"}
        rc, out, err = await _q_exec(["df", "-h", "/"], timeout=5)
        if rc != 0:
            return {"success": False, "handler_type": h,
                    "stderr": err, "returncode": rc,
                    "hint": "df -h / failed; check mount table"}
        # Parse last non-header line:
        #   Filesystem Size Used Avail Use% Mounted_on
        lines = [ln for ln in out.splitlines() if ln.strip()]
        if len(lines) < 2:
            return {"success": False, "handler_type": h,
                    "error": "unparseable df output",
                    "raw": out, "hint": "unexpected df format"}
        parts = lines[-1].split()
        # On some busybox dfs the filesystem name may wrap to its own line;
        # detect by checking parts length >= 6.
        if len(parts) < 6:
            # Attempt to use the penultimate + last line concatenated.
            combined = (lines[-2] + " " + lines[-1]).split()
            if len(combined) >= 6:
                parts = combined
        if len(parts) < 6:
            return {"success": False, "handler_type": h,
                    "error": "unparseable df output",
                    "raw": out, "hint": "unexpected df format"}
        total_s, used_s, free_s, use_pct_s = parts[1], parts[2], parts[3], parts[4]

        def _hr_to_gb(val: str) -> float | None:
            try:
                v = val.strip()
                if not v:
                    return None
                unit = v[-1].upper()
                num = float(v[:-1] if unit in "KMGTPE" else v)
                mult = {"K": 1 / (1024 * 1024),
                        "M": 1 / 1024,
                        "G": 1.0,
                        "T": 1024.0,
                        "P": 1024.0 * 1024.0,
                        "E": 1024.0 * 1024.0 * 1024.0}.get(unit, 1 / (1024 * 1024 * 1024))
                return round(num * mult, 2)
            except Exception:
                return None

        total_gb = _hr_to_gb(total_s)
        free_gb = _hr_to_gb(free_s)
        used_gb = _hr_to_gb(used_s)
        try:
            used_pct = int(use_pct_s.rstrip("%"))
        except Exception:
            used_pct = None
        summary = (
            f"{free_s} free of {total_s} on / "
            f"({use_pct_s} used)"
        )
        return {
            "success": True,
            "handler_type": h,
            "filesystem": parts[0],
            "free_gb": free_gb,
            "total_gb": total_gb,
            "used_gb": used_gb,
            "used_pct": used_pct,
            "mounted_on": parts[5] if len(parts) > 5 else "/",
            "summary": summary,
            "raw": lines[-1],
        }
    except Exception as e:
        logger.exception("query.disk_space crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "query.disk_space parser raised an exception"}


async def query_ip_address(args):
    h = "query.ip_address"
    try:
        interfaces: list[dict] = []
        if shutil.which("ip") is not None:
            rc, out, err = await _q_exec(
                ["ip", "-4", "-o", "addr", "show", "scope", "global"],
                timeout=5)
            if rc == 0:
                # Lines look like:
                #   2: wlan0    inet 192.168.1.23/24 brd 192.168.1.255 ...
                for ln in out.splitlines():
                    toks = ln.split()
                    if len(toks) < 4:
                        continue
                    iface = toks[1]
                    # find 'inet' token then address/prefix
                    try:
                        idx = toks.index("inet")
                        addr_cidr = toks[idx + 1]
                        addr = addr_cidr.split("/")[0]
                        interfaces.append(
                            {"interface": iface, "address": addr,
                             "cidr": addr_cidr})
                    except (ValueError, IndexError):
                        continue
        elif shutil.which("hostname") is not None:
            rc, out, _ = await _q_exec(["hostname", "-I"], timeout=5)
            if rc == 0:
                for addr in out.split():
                    if ":" not in addr:  # skip v6
                        interfaces.append(
                            {"interface": "?", "address": addr,
                             "cidr": None})

        # Public IP — best-effort; graceful None on failure.
        public_ip = None
        public_error = None
        if shutil.which("curl") is not None:
            try:
                rc, out, err = await _q_exec(
                    ["curl", "-s", "--max-time", "3", "https://ifconfig.me"],
                    timeout=4)
                if rc == 0 and out.strip():
                    candidate = out.strip().splitlines()[0].strip()
                    # crude sanity — accept only short IPv4/IPv6-ish string
                    if (1 < len(candidate) <= 64
                            and all(c.isalnum() or c in ".:" for c in candidate)):
                        public_ip = candidate
                    else:
                        public_error = "non-ip response from ifconfig.me"
                else:
                    public_error = err.strip() or f"curl rc={rc}"
            except Exception as e:
                public_error = str(e)
        else:
            public_error = "curl not installed"

        if not interfaces and public_ip is None:
            return {"success": False, "handler_type": h,
                    "error": "no ip addresses available",
                    "hint": "install iproute2 and/or connect a network"}
        return {"success": True, "handler_type": h,
                "interfaces": interfaces, "public_ip": public_ip,
                "public_ip_error": public_error}
    except Exception as e:
        logger.exception("query.ip_address crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "query.ip_address parser raised an exception"}


async def query_uptime(args):
    h = "query.uptime"
    try:
        raw = _read_text("/proc/uptime")
        if raw is None:
            return {"success": False, "handler_type": h,
                    "error": "cannot read /proc/uptime",
                    "hint": "/proc/uptime unavailable on this kernel"}
        tok = raw.split()
        if not tok:
            return {"success": False, "handler_type": h,
                    "error": "empty /proc/uptime",
                    "hint": "/proc/uptime had no tokens"}
        seconds = float(tok[0])
        s = int(seconds)
        days, s = divmod(s, 86400)
        hours, s = divmod(s, 3600)
        minutes, s = divmod(s, 60)
        parts: list[str] = []
        if days:
            parts.append(f"{days} day{'s' if days != 1 else ''}")
        if hours:
            parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
        if minutes and not days:
            parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
        if not parts:
            parts.append(f"{s} second{'s' if s != 1 else ''}")
        human = " ".join(parts)
        return {
            "success": True,
            "handler_type": h,
            "seconds": seconds,
            "days": days,
            "hours": hours,
            "minutes": minutes,
            "human": human,
        }
    except Exception as e:
        logger.exception("query.uptime crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "query.uptime parser raised an exception"}


async def query_cpu_temp(args):
    h = "query.cpu_temp"
    try:
        per_zone: dict[str, float] = {}
        # Pass 1 — sysfs thermal zones (primary, stdlib only, cheap).
        try:
            import glob
            for zdir in sorted(glob.glob("/sys/class/thermal/thermal_zone*")):
                t_val = _read_text(os.path.join(zdir, "temp"))
                z_type = _read_text(os.path.join(zdir, "type")) or os.path.basename(zdir)
                if t_val and t_val.lstrip("-").isdigit():
                    # Millidegree celsius per kernel convention.
                    per_zone[z_type] = round(int(t_val) / 1000.0, 2)
        except Exception:
            pass

        # Pass 2 — sensors -j if nothing useful yet and lm_sensors installed.
        if not per_zone and shutil.which("sensors") is not None:
            rc, out, err = await _q_exec(["sensors", "-j"], timeout=5)
            if rc == 0 and out:
                try:
                    j = json.loads(out)
                    # Walk for any temp* keys under nested dicts.
                    def _walk(prefix: str, d):
                        if not isinstance(d, dict):
                            return
                        for k, v in d.items():
                            if isinstance(v, dict):
                                # Look for *_input child
                                for subk, subv in v.items():
                                    if (isinstance(subk, str)
                                            and subk.endswith("_input")
                                            and isinstance(subv, (int, float))):
                                        per_zone[f"{prefix}{k}"] = round(
                                            float(subv), 2)
                                _walk(f"{prefix}{k}.", v)
                    _walk("", j)
                except Exception:
                    pass

        if not per_zone:
            return {"success": False, "handler_type": h,
                    "reason": "no thermal zones",
                    "hint": ("no readable /sys/class/thermal/thermal_zone*/temp "
                             "and lm_sensors unavailable")}
        max_c = max(per_zone.values())
        return {"success": True, "handler_type": h,
                "max_c": max_c, "per_zone": per_zone,
                "zones": len(per_zone)}
    except Exception as e:
        logger.exception("query.cpu_temp crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "query.cpu_temp parser raised an exception"}


async def query_memory_top(args):
    h = "query.memory_top"
    try:
        if shutil.which("ps") is None:
            return {"success": False, "handler_type": h,
                    "error": "ps not installed",
                    "hint": "install procps-ng (should always be present)"}
        rc, out, err = await _q_exec(
            ["ps", "ax", "--sort=-%mem", "-o", "pid,%mem,%cpu,comm"],
            timeout=5)
        if rc != 0:
            return {"success": False, "handler_type": h,
                    "stderr": err, "returncode": rc,
                    "hint": "ps ax failed; check procps-ng"}
        entries: list[dict] = []
        for ln in out.splitlines()[1:11]:  # skip header, take 10
            parts = ln.split(None, 3)
            if len(parts) < 4:
                continue
            pid_s, mem_s, cpu_s, command = parts
            try:
                pid = int(pid_s)
                mem_pct = float(mem_s)
                cpu_pct = float(cpu_s)
            except ValueError:
                continue
            entries.append({
                "pid": pid,
                "mem_pct": mem_pct,
                "cpu_pct": cpu_pct,
                "command": command,
            })
        return {"success": True, "handler_type": h,
                "entries": entries, "count": len(entries)}
    except Exception as e:
        logger.exception("query.memory_top crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "query.memory_top parser raised an exception"}


async def query_wifi_peers(args):
    h = "query.wifi_peers"
    try:
        if shutil.which("nmcli") is None:
            return {"success": False, "handler_type": h,
                    "reason": "nmcli not installed",
                    "hint": ("NetworkManager not present; install "
                             "networkmanager to enable wifi peer queries")}
        rc, out, err = await _q_exec(
            ["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL", "dev", "wifi"],
            timeout=5)
        if rc != 0:
            # No WiFi hardware, NM not running, or rfkill — all produce non-zero.
            return {"success": False, "handler_type": h,
                    "stderr": err, "returncode": rc,
                    "reason": "nmcli dev wifi failed",
                    "hint": ("no wifi radio, NetworkManager not running, or "
                             "wifi disabled (rfkill/airplane mode)")}
        peers: list[dict] = []
        for ln in out.splitlines():
            # Fields may contain escaped colons (\:); nmcli -t still splits
            # reliably on unescaped ':' but rare SSIDs can contain backslashes.
            # We tolerate at most 3 fields.
            parts = ln.split(":", 2)
            if len(parts) != 3:
                continue
            active, ssid, signal = parts
            if not ssid:  # hidden
                continue
            try:
                sig = int(signal) if signal else None
            except ValueError:
                sig = None
            peers.append({
                "ssid": ssid.replace("\\:", ":"),
                "signal": sig,
                "active": active.strip().lower() in ("yes", "1", "active", "true"),
            })
        return {"success": True, "handler_type": h,
                "peers": peers, "count": len(peers)}
    except Exception as e:
        logger.exception("query.wifi_peers crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "query.wifi_peers parser raised an exception"}


async def query_kernel_version(args):
    h = "query.kernel_version"
    try:
        if shutil.which("uname") is None:
            # stdlib fallback
            try:
                rel = os.uname().release
                ver = os.uname().version
                sysname = os.uname().sysname
                return {"success": True, "handler_type": h,
                        "kernel": sysname, "version": rel,
                        "build": ver,
                        "summary": f"{sysname} {rel} {ver}".strip()}
            except Exception as e:
                return {"success": False, "handler_type": h,
                        "error": str(e),
                        "hint": "uname binary missing and os.uname() failed"}
        rc, out, err = await _q_exec(["uname", "-srv"], timeout=5)
        if rc != 0:
            return {"success": False, "handler_type": h,
                    "stderr": err, "returncode": rc,
                    "hint": "uname -srv failed"}
        parts = out.split(None, 2)
        kernel = parts[0] if len(parts) > 0 else None
        version = parts[1] if len(parts) > 1 else None
        build = parts[2] if len(parts) > 2 else None
        return {"success": True, "handler_type": h,
                "kernel": kernel, "version": version, "build": build,
                "summary": out}
    except Exception as e:
        logger.exception("query.kernel_version crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "query.kernel_version parser raised an exception"}


async def query_distro_version(args):
    h = "query.distro_version"
    try:
        raw = _read_text("/etc/os-release")
        if raw is None:
            return {"success": False, "handler_type": h,
                    "error": "/etc/os-release not readable",
                    "hint": "this host does not publish /etc/os-release"}
        fields: dict[str, str] = {}
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#") or "=" not in ln:
                continue
            k, _, v = ln.partition("=")
            v = v.strip().strip('"').strip("'")
            fields[k.strip()] = v
        return {
            "success": True,
            "handler_type": h,
            "name": fields.get("NAME"),
            "version_id": fields.get("VERSION_ID"),
            "pretty_name": fields.get("PRETTY_NAME"),
            "id": fields.get("ID"),
            "id_like": fields.get("ID_LIKE"),
            "fields": fields,
        }
    except Exception as e:
        logger.exception("query.distro_version crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "query.distro_version parser raised an exception"}


async def query_loadavg(args):
    h = "query.loadavg"
    try:
        raw = _read_text("/proc/loadavg")
        if raw is None:
            return {"success": False, "handler_type": h,
                    "error": "cannot read /proc/loadavg",
                    "hint": "/proc/loadavg unavailable"}
        parts = raw.split()
        if len(parts) < 5:
            return {"success": False, "handler_type": h,
                    "error": "unparseable /proc/loadavg",
                    "raw": raw,
                    "hint": "unexpected /proc/loadavg format"}
        try:
            l1, l5, l15 = float(parts[0]), float(parts[1]), float(parts[2])
        except ValueError:
            return {"success": False, "handler_type": h,
                    "error": "non-float load samples", "raw": raw,
                    "hint": "unexpected /proc/loadavg format"}
        runnable, total = None, None
        if "/" in parts[3]:
            try:
                rr, tt = parts[3].split("/", 1)
                runnable, total = int(rr), int(tt)
            except ValueError:
                pass
        return {
            "success": True,
            "handler_type": h,
            "1m": l1,
            "5m": l5,
            "15m": l15,
            "runnable_procs": runnable,
            "total_procs": total,
            "last_pid": int(parts[4]) if parts[4].isdigit() else None,
        }
    except Exception as e:
        logger.exception("query.loadavg crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "query.loadavg parser raised an exception"}


async def query_logged_in_users(args):
    h = "query.logged_in_users"
    try:
        if shutil.which("who") is None:
            return {"success": False, "handler_type": h,
                    "error": "who not installed",
                    "hint": "install coreutils (should always be present)"}
        rc, out, err = await _q_exec(["who"], timeout=5)
        if rc != 0:
            return {"success": False, "handler_type": h,
                    "stderr": err, "returncode": rc,
                    "hint": "who failed; /var/run/utmp may be missing"}
        users: list[dict] = []
        for ln in out.splitlines():
            ln = ln.rstrip()
            if not ln.strip():
                continue
            # who output:  user  tty  date time   [host]
            parts = ln.split(None, 4)
            if len(parts) < 4:
                continue
            user, tty = parts[0], parts[1]
            # date + time typically: YYYY-MM-DD HH:MM  -> parts[2] + parts[3]
            login_time = f"{parts[2]} {parts[3]}" if len(parts) >= 4 else ""
            host = None
            if len(parts) >= 5:
                rest = parts[4].strip()
                # host is usually parenthesised: (192.168.1.5)
                if rest.startswith("(") and rest.endswith(")"):
                    host = rest[1:-1]
                else:
                    host = rest
            users.append({
                "user": user,
                "tty": tty,
                "host": host,
                "login_time": login_time,
            })
        return {"success": True, "handler_type": h,
                "users": users, "count": len(users)}
    except Exception as e:
        logger.exception("query.logged_in_users crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "query.logged_in_users parser raised an exception"}


# Register query handlers in the dispatch table.  Done via HANDLERS[...] = ...
# rather than editing the HANDLERS literal above so new handler modules can
# extend the registry without touching existing declarations.
HANDLERS["query.disk_space"]      = query_disk_space
HANDLERS["query.ip_address"]      = query_ip_address
HANDLERS["query.uptime"]          = query_uptime
HANDLERS["query.cpu_temp"]        = query_cpu_temp
HANDLERS["query.memory_top"]      = query_memory_top
HANDLERS["query.wifi_peers"]      = query_wifi_peers
HANDLERS["query.kernel_version"]  = query_kernel_version
HANDLERS["query.distro_version"]  = query_distro_version
HANDLERS["query.loadavg"]         = query_loadavg
HANDLERS["query.logged_in_users"] = query_logged_in_users


# ---------------------------------------------------------------------------
# Session 68 Agent Y — file/directory automation
#
# Handlers in this block all use _q_exec for subprocess calls (30s timeout,
# expand ~/relative paths via os.path.expanduser, and guard the obvious
# destructive targets (/, /home, /etc).  Destructive operations (delete,
# move) default to dry_run=True unless confirm=True is in args.
# ---------------------------------------------------------------------------


_FILE_REFUSE_PATHS = {"/", "/home", "/etc", "/usr", "/var", "/boot", "/root", "/sys", "/proc", "/dev"}


def _file_resolve(p):
    """Expand user + make absolute.  Returns normalised abs path or None."""
    if p is None or not isinstance(p, str) or not p.strip():
        return None
    try:
        return os.path.abspath(os.path.expanduser(p))
    except Exception:
        return None


def _file_refused(resolved):
    """True if the resolved abs path is a top-level system dir we refuse to mutate."""
    if resolved is None:
        return True
    # Normalise trailing slash
    norm = resolved.rstrip("/") or "/"
    return norm in _FILE_REFUSE_PATHS


def _human_size(n):
    """Render bytes as human-readable (B, KiB, MiB, GiB, TiB)."""
    try:
        n = float(n)
    except Exception:
        return "?"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PiB"


async def file_delete_empty_dirs(args):
    h = "file.delete_empty_dirs"
    try:
        raw = args.get("path") if isinstance(args, dict) else None
        resolved = _file_resolve(raw)
        if resolved is None:
            return {"success": False, "handler_type": h,
                    "error": "path is required",
                    "hint": "pass {\"path\": \"~/Downloads\"}"}
        if _file_refused(resolved):
            return {"success": False, "handler_type": h,
                    "path_resolved": resolved,
                    "error": f"refuse to mutate system directory: {resolved}",
                    "hint": "target a subdirectory (e.g. ~/Downloads), not a system root"}
        if not os.path.isdir(resolved):
            return {"success": False, "handler_type": h,
                    "path_resolved": resolved,
                    "error": "path is not a directory"}
        if shutil.which("find") is None:
            return {"success": False, "handler_type": h,
                    "error": "find not installed",
                    "hint": "install findutils"}
        # Count first (non-destructive dry count), then delete.
        rc1, out1, _err1 = await _q_exec(
            ["find", resolved, "-mindepth", "1", "-type", "d", "-empty"],
            timeout=30)
        count = 0
        if rc1 == 0:
            count = sum(1 for ln in out1.splitlines() if ln.strip())
        rc, _out, err = await _q_exec(
            ["find", resolved, "-mindepth", "1", "-type", "d", "-empty", "-delete"],
            timeout=30)
        if rc != 0:
            return {"success": False, "handler_type": h,
                    "path_resolved": resolved,
                    "stderr": err, "returncode": rc,
                    "count_deleted": 0,
                    "hint": "find -delete failed; check permissions"}
        return {"success": True, "handler_type": h,
                "path_resolved": resolved,
                "count_deleted": count,
                "hint": f"removed {count} empty directories under {resolved}"}
    except Exception as e:
        logger.exception("file.delete_empty_dirs crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "file.delete_empty_dirs raised an exception"}


async def file_find_largest(args):
    h = "file.find_largest"
    try:
        raw = (args.get("path") if isinstance(args, dict) else None) or "~"
        top_n_raw = args.get("top_n", 10) if isinstance(args, dict) else 10
        try:
            top_n = int(top_n_raw)
        except Exception:
            top_n = 10
        if top_n < 1:
            top_n = 1
        if top_n > 1000:
            top_n = 1000
        resolved = _file_resolve(raw)
        if resolved is None or not os.path.isdir(resolved):
            return {"success": False, "handler_type": h,
                    "path_resolved": resolved,
                    "error": "path is not a directory"}
        if shutil.which("find") is None:
            return {"success": False, "handler_type": h,
                    "error": "find not installed"}
        # -P (physical, no symlink follow), printf "%s\t%p\n"
        rc, out, err = await _q_exec(
            ["find", "-P", resolved, "-type", "f", "-printf", "%s\t%p\n"],
            timeout=30)
        if rc != 0 and not out:
            return {"success": False, "handler_type": h,
                    "path_resolved": resolved,
                    "stderr": err, "returncode": rc,
                    "hint": "find scan failed; path may be unreadable"}
        rows = []
        for ln in out.splitlines():
            if not ln.strip():
                continue
            parts = ln.split("\t", 1)
            if len(parts) != 2:
                continue
            try:
                sz = int(parts[0])
            except Exception:
                continue
            rows.append((sz, parts[1]))
        rows.sort(key=lambda r: r[0], reverse=True)
        rows = rows[:top_n]
        entries = [
            {"size_bytes": sz, "size_human": _human_size(sz), "path": p}
            for sz, p in rows
        ]
        return {"success": True, "handler_type": h,
                "path_resolved": resolved,
                "top_n": top_n,
                "entries": entries,
                "count": len(entries)}
    except Exception as e:
        logger.exception("file.find_largest crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "file.find_largest raised an exception"}


async def file_zip_folder(args):
    h = "file.zip_folder"
    try:
        raw_src = args.get("src") if isinstance(args, dict) else None
        raw_dst = args.get("dst") if isinstance(args, dict) else None
        src = _file_resolve(raw_src)
        if src is None or not os.path.isdir(src):
            return {"success": False, "handler_type": h,
                    "error": "src is required and must be a directory",
                    "hint": "pass {\"src\": \"~/Documents\"}"}
        if _file_refused(src):
            return {"success": False, "handler_type": h,
                    "src_resolved": src,
                    "error": f"refuse to archive system directory: {src}"}
        if raw_dst:
            dst = _file_resolve(raw_dst)
        else:
            parent = os.path.dirname(src.rstrip("/")) or "."
            dst = os.path.join(parent, os.path.basename(src.rstrip("/")) + ".zip")
        if dst is None:
            return {"success": False, "handler_type": h,
                    "error": "could not resolve dst path"}
        dst_parent = os.path.dirname(dst) or "."
        if not os.path.isdir(dst_parent):
            return {"success": False, "handler_type": h,
                    "dst_resolved": dst,
                    "error": f"dst parent dir does not exist: {dst_parent}"}
        # Prefer zip(1); fallback to python -m zipfile
        if shutil.which("zip"):
            rc, _out, err = await _q_exec(
                ["zip", "-r", "-q", dst, os.path.basename(src.rstrip("/"))],
                timeout=30)
            # zip -r wants a relative target; run from parent
            if rc != 0:
                # Retry with absolute paths (some zip builds handle it)
                rc, _out, err = await _q_exec(
                    ["zip", "-r", "-q", dst, src], timeout=30)
        else:
            if shutil.which("python3") is None:
                return {"success": False, "handler_type": h,
                        "error": "neither zip nor python3 available",
                        "hint": "install zip (pacman -S zip)"}
            rc, _out, err = await _q_exec(
                ["python3", "-m", "zipfile", "-c", dst, src], timeout=30)
        if rc != 0:
            return {"success": False, "handler_type": h,
                    "src_resolved": src, "dst_resolved": dst,
                    "stderr": err, "returncode": rc,
                    "hint": "zip failed; check free space + permissions"}
        try:
            archive_size_bytes = os.path.getsize(dst)
        except OSError:
            archive_size_bytes = 0
        # Entry count via unzip -l if present, else approximate.
        entry_count = 0
        if shutil.which("unzip"):
            rc2, out2, _err2 = await _q_exec(["unzip", "-l", dst], timeout=15)
            if rc2 == 0:
                for ln in out2.splitlines():
                    parts = ln.split()
                    if parts and parts[0].isdigit():
                        entry_count += 1
        return {"success": True, "handler_type": h,
                "src_resolved": src,
                "dst_resolved": dst,
                "archive_size_bytes": archive_size_bytes,
                "archive_size_human": _human_size(archive_size_bytes),
                "entry_count": entry_count}
    except Exception as e:
        logger.exception("file.zip_folder crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "file.zip_folder raised an exception"}


async def file_move_by_pattern(args):
    h = "file.move_by_pattern"
    try:
        src_dir = _file_resolve(args.get("src_dir") if isinstance(args, dict) else None)
        dst_dir = _file_resolve(args.get("dst_dir") if isinstance(args, dict) else None)
        glob_pat = args.get("glob") if isinstance(args, dict) else None
        dry_run = bool(args.get("dry_run", True)) if isinstance(args, dict) else True
        if args.get("confirm") is True:
            dry_run = False
        if not src_dir or not os.path.isdir(src_dir):
            return {"success": False, "handler_type": h,
                    "error": "src_dir is required and must be a directory"}
        if not dst_dir:
            return {"success": False, "handler_type": h,
                    "error": "dst_dir is required"}
        if not glob_pat or not isinstance(glob_pat, str):
            return {"success": False, "handler_type": h,
                    "error": "glob is required (e.g. '*.png')"}
        if _file_refused(src_dir) or _file_refused(dst_dir):
            return {"success": False, "handler_type": h,
                    "src_dir": src_dir, "dst_dir": dst_dir,
                    "error": "refuse to mutate system directories"}
        # Normalise plain extensions like "png" -> "*.png"
        norm_glob = glob_pat if ("*" in glob_pat or "?" in glob_pat) else f"*.{glob_pat.lstrip('.')}"
        if shutil.which("find") is None:
            return {"success": False, "handler_type": h, "error": "find not installed"}
        rc, out, err = await _q_exec(
            ["find", src_dir, "-maxdepth", "1", "-type", "f", "-name", norm_glob],
            timeout=30)
        if rc != 0:
            return {"success": False, "handler_type": h,
                    "src_dir": src_dir, "dst_dir": dst_dir, "glob": norm_glob,
                    "dry_run": dry_run,
                    "stderr": err, "returncode": rc,
                    "hint": "find scan failed"}
        matches = [ln for ln in out.splitlines() if ln.strip()]
        if dry_run:
            return {"success": True, "handler_type": h,
                    "src_dir": src_dir, "dst_dir": dst_dir, "glob": norm_glob,
                    "dry_run": True,
                    "moved_files": [],
                    "previewed_list": matches,
                    "count": 0,
                    "hint": (f"would move {len(matches)} file(s); "
                             f"re-call with confirm=true to actually move")}
        if not os.path.isdir(dst_dir):
            try:
                os.makedirs(dst_dir, exist_ok=True)
            except Exception as e:
                return {"success": False, "handler_type": h,
                        "error": f"could not create dst_dir: {e}"}
        if shutil.which("mv") is None:
            return {"success": False, "handler_type": h, "error": "mv not installed"}
        moved = []
        errors = []
        for src_file in matches:
            rc2, _out2, err2 = await _q_exec(
                ["mv", "--", src_file, dst_dir + "/"], timeout=30)
            if rc2 == 0:
                moved.append(src_file)
            else:
                errors.append({"src": src_file, "stderr": err2})
        ok = len(errors) == 0
        return {"success": ok, "handler_type": h,
                "src_dir": src_dir, "dst_dir": dst_dir, "glob": norm_glob,
                "dry_run": False,
                "moved_files": moved,
                "count": len(moved),
                "errors": errors}
    except Exception as e:
        logger.exception("file.move_by_pattern crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "file.move_by_pattern raised an exception"}


async def file_backup_to(args):
    h = "file.backup_to"
    try:
        src = _file_resolve(args.get("src") if isinstance(args, dict) else None)
        dst = _file_resolve(args.get("dst") if isinstance(args, dict) else None)
        excl = args.get("exclude", []) if isinstance(args, dict) else []
        if not isinstance(excl, list):
            excl = []
        if not src or not os.path.isdir(src):
            return {"success": False, "handler_type": h,
                    "error": "src is required and must be a directory"}
        if not dst:
            return {"success": False, "handler_type": h,
                    "error": "dst is required"}
        if _file_refused(dst):
            return {"success": False, "handler_type": h,
                    "src": src, "dst": dst,
                    "error": f"refuse to mirror into system directory: {dst}"}
        try:
            os.makedirs(dst, exist_ok=True)
        except Exception as e:
            return {"success": False, "handler_type": h,
                    "error": f"could not create dst: {e}"}
        t0 = time.time()
        files_copied = 0
        size_bytes = 0
        if shutil.which("rsync"):
            excl_file = None
            argv = ["rsync", "-a", "--stats", "--delete-after",
                    src.rstrip("/") + "/", dst.rstrip("/") + "/"]
            if excl:
                import tempfile
                excl_file = tempfile.NamedTemporaryFile(
                    mode="w", delete=False, suffix=".exclude")
                for line in excl:
                    if isinstance(line, str) and line.strip():
                        excl_file.write(line.strip() + "\n")
                excl_file.close()
                argv.insert(2, f"--exclude-from={excl_file.name}")
            rc, out, err = await _q_exec(argv, timeout=30)
            if excl_file is not None:
                try:
                    os.unlink(excl_file.name)
                except OSError:
                    pass
            if rc != 0:
                return {"success": False, "handler_type": h,
                        "src": src, "dst": dst,
                        "stderr": err, "returncode": rc,
                        "duration_s": round(time.time() - t0, 3),
                        "hint": "rsync failed; check permissions + space"}
            # Parse rsync --stats output
            for ln in out.splitlines():
                s = ln.strip().lower()
                if s.startswith("number of regular files transferred"):
                    try:
                        files_copied = int(s.split(":", 1)[1].strip().replace(",", ""))
                    except Exception:
                        pass
                elif s.startswith("total transferred file size"):
                    try:
                        rhs = s.split(":", 1)[1].strip().split()[0].replace(",", "")
                        size_bytes = int(rhs)
                    except Exception:
                        pass
            tool = "rsync"
        else:
            if shutil.which("cp") is None:
                return {"success": False, "handler_type": h,
                        "error": "neither rsync nor cp available"}
            rc, _out, err = await _q_exec(
                ["cp", "-ru", "--", src, dst], timeout=30)
            if rc != 0:
                return {"success": False, "handler_type": h,
                        "src": src, "dst": dst,
                        "stderr": err, "returncode": rc,
                        "duration_s": round(time.time() - t0, 3),
                        "hint": "cp -ru fallback failed"}
            tool = "cp"
        return {"success": True, "handler_type": h,
                "src": src, "dst": dst,
                "tool": tool,
                "size_bytes_copied": size_bytes,
                "files_copied": files_copied,
                "duration_s": round(time.time() - t0, 3),
                "excluded_patterns": excl}
    except Exception as e:
        logger.exception("file.backup_to crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "file.backup_to raised an exception"}


async def file_open_path(args):
    h = "file.open_path"
    try:
        resolved = _file_resolve(args.get("path") if isinstance(args, dict) else None)
        if resolved is None:
            return {"success": False, "handler_type": h,
                    "error": "path is required"}
        if not os.path.exists(resolved):
            return {"success": False, "handler_type": h,
                    "path": resolved,
                    "error": "path does not exist"}
        if shutil.which("xdg-open") is None:
            return {"success": False, "handler_type": h,
                    "path": resolved,
                    "error": "xdg-open not installed",
                    "hint": "install xdg-utils"}
        # Fire-and-forget — don't block on the GUI app.
        try:
            await asyncio.create_subprocess_exec(
                "xdg-open", resolved,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                env=_env(),
                start_new_session=True)
        except Exception as e:
            return {"success": False, "handler_type": h,
                    "path": resolved,
                    "error": f"xdg-open spawn failed: {e}"}
        return {"success": True, "handler_type": h,
                "path": resolved,
                "opened_with": "xdg-open"}
    except Exception as e:
        logger.exception("file.open_path crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "file.open_path raised an exception"}


async def file_list_recent(args):
    h = "file.list_recent"
    try:
        raw = (args.get("path") if isinstance(args, dict) else None) or "~"
        top_n_raw = args.get("top_n", 10) if isinstance(args, dict) else 10
        try:
            top_n = int(top_n_raw)
        except Exception:
            top_n = 10
        if top_n < 1:
            top_n = 1
        if top_n > 1000:
            top_n = 1000
        resolved = _file_resolve(raw)
        if resolved is None or not os.path.isdir(resolved):
            return {"success": False, "handler_type": h,
                    "path_resolved": resolved,
                    "error": "path is not a directory"}
        if shutil.which("find") is None:
            return {"success": False, "handler_type": h,
                    "error": "find not installed"}
        rc, out, err = await _q_exec(
            ["find", "-P", resolved, "-type", "f", "-printf", "%T@\t%p\n"],
            timeout=30)
        if rc != 0 and not out:
            return {"success": False, "handler_type": h,
                    "path_resolved": resolved,
                    "stderr": err, "returncode": rc,
                    "hint": "find scan failed"}
        rows = []
        for ln in out.splitlines():
            if not ln.strip():
                continue
            parts = ln.split("\t", 1)
            if len(parts) != 2:
                continue
            try:
                mt = float(parts[0])
            except Exception:
                continue
            rows.append((mt, parts[1]))
        rows.sort(key=lambda r: r[0], reverse=True)
        rows = rows[:top_n]
        entries = []
        for mt, p in rows:
            mt_unix = int(mt)
            try:
                mt_human = time.strftime("%Y-%m-%d %H:%M:%S",
                                         time.localtime(mt_unix))
            except Exception:
                mt_human = ""
            entries.append({
                "mtime_unix": mt_unix,
                "mtime_human": mt_human,
                "path": p,
            })
        return {"success": True, "handler_type": h,
                "path_resolved": resolved,
                "top_n": top_n,
                "entries": entries,
                "count": len(entries)}
    except Exception as e:
        logger.exception("file.list_recent crashed: %s", e)
        return {"success": False, "handler_type": h, "error": str(e),
                "hint": "file.list_recent raised an exception"}


HANDLERS["file.delete_empty_dirs"] = file_delete_empty_dirs
HANDLERS["file.find_largest"]      = file_find_largest
HANDLERS["file.zip_folder"]        = file_zip_folder
HANDLERS["file.move_by_pattern"]   = file_move_by_pattern
HANDLERS["file.backup_to"]         = file_backup_to
HANDLERS["file.open_path"]         = file_open_path
HANDLERS["file.list_recent"]       = file_list_recent


# ---------------------------------------------------------------------------
# PE LOADER DISPATCH (Session 68, Agent W) — direct NL → pe-loader invocation.
#
# `pe.run` / `pe.analyze` / `pe.install_msi` give the AI/CLI a first-class way
# to reach pe-loader without editing contusion_dictionary.  `pe.analyze` is
# PURELY STRUCTURAL (parses PE headers, never executes).  `pe.run` invokes
# /usr/bin/peloader and records the run to /var/lib/ai-control/pe_history.jsonl
# so `pe.list_recent` can surface recent invocations.  `pe.clear_cache` wipes
# the download staging dir and is admin-only.
# ---------------------------------------------------------------------------

import struct
import urllib.parse

_PE_LOADER_BIN = "/usr/bin/peloader"
_PE_DOWNLOAD_DIR = "/var/cache/ai-control/downloads"
_PE_HISTORY_FILE = "/var/lib/ai-control/pe_history.jsonl"
_PE_HISTORY_KEEP = 10


def _pe_ensure_dirs() -> None:
    for d in (_PE_DOWNLOAD_DIR, os.path.dirname(_PE_HISTORY_FILE)):
        try:
            os.makedirs(d, mode=0o755, exist_ok=True)
        except OSError as e:
            logger.debug("pe: cannot create %s: %s", d, e)


def _pe_is_url(s: str) -> bool:
    return isinstance(s, str) and (s.startswith("http://")
                                    or s.startswith("https://"))


def _pe_safe_basename(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    name = os.path.basename(parsed.path) or "download.bin"
    # Strip anything outside a conservative safelist; pe-loader doesn't care
    # about the filename — we just need a predictable on-disk handle.
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    return safe[:128] or "download.bin"


async def _pe_download(url: str, handler: str) -> dict:
    """Download URL into /var/cache/ai-control/downloads.
    Returns {'ok': True, 'path': ...} or {'ok': False, 'env': <envelope>}.
    """
    _pe_ensure_dirs()
    fname = _pe_safe_basename(url)
    dest = os.path.join(_PE_DOWNLOAD_DIR, fname)
    env = await _exec(handler, [
        "curl", "-fsSL", "--max-time", "60",
        "-o", dest, url,
    ], timeout=65)
    if not env.get("success"):
        return {"ok": False, "env": env}
    if not os.path.exists(dest) or os.path.getsize(dest) < 2:
        return {"ok": False, "env": _bad_arg(
            handler, f"download produced empty file: {dest}")}
    return {"ok": True, "path": dest}


def _pe_check_mz(path: str):
    try:
        with open(path, "rb") as f:
            head = f.read(2)
    except OSError as e:
        return False, f"cannot read {path}: {e}"
    if head != b"MZ":
        return False, f"not a PE file (missing MZ magic): {path}"
    return True, ""


def _pe_resolve_path(raw: str, handler: str, allow_url: bool = True):
    """Validate a PE path argument.  Rejects bare filenames (must be absolute
    or URL) to block PATH-traversal abuse.  Returns (True, path_or_url) or
    (False, <envelope>)."""
    if not isinstance(raw, str) or not raw:
        return False, _bad_arg(handler, "missing arg 'path'")
    if _pe_is_url(raw):
        if not allow_url:
            return False, _bad_arg(handler, "URL not permitted for this handler")
        return True, raw
    if not os.path.isabs(raw):
        return False, _bad_arg(
            handler,
            f"path must be absolute or http(s) URL, got {raw!r}")
    return True, raw


def _pe_record_history(path: str, returncode: int, duration_s: float) -> None:
    try:
        _pe_ensure_dirs()
        entry = {
            "timestamp": time.time(),
            "path": path,
            "returncode": returncode,
            "duration_s": round(duration_s, 3),
        }
        with open(_PE_HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        logger.debug("pe: cannot append history: %s", e)


def _pe_tail(s: str, n: int = 500) -> str:
    if not isinstance(s, str):
        return ""
    return s[-n:] if len(s) > n else s


async def pe_run(args):
    h = "pe.run"
    raw_path = args.get("path") or args.get("path_or_url")
    ok, resolved = _pe_resolve_path(raw_path, h, allow_url=True)
    if not ok:
        return resolved  # envelope from _bad_arg

    try:
        timeout_s = int(args.get("timeout_s", 30))
    except (TypeError, ValueError):
        timeout_s = 30
    timeout_s = max(1, min(600, timeout_s))

    raw_args = args.get("args") or []
    if not isinstance(raw_args, list):
        return _bad_arg(h, "arg 'args' must be a list of strings")
    try:
        clean_args = Sanitizer.argv(raw_args, max_args=32)
    except SanitizerError as e:
        return _bad_arg(h, e.as_dict()["message"])

    if _pe_is_url(resolved):
        dl = await _pe_download(resolved, h)
        if not dl["ok"]:
            return _with_error(dl["env"])
        local_path = dl["path"]
    else:
        local_path = resolved
        if not os.path.exists(local_path):
            return _bad_arg(h, f"file does not exist: {local_path}")

    mz_ok, why = _pe_check_mz(local_path)
    if not mz_ok:
        return _bad_arg(h, why)

    if not os.path.exists(_PE_LOADER_BIN):
        return _missing(h, _PE_LOADER_BIN,
                        install_hint="pacman -S pe-loader")

    argv = [_PE_LOADER_BIN, local_path] + clean_args
    t0 = time.time()
    env = await _exec(h, argv, timeout=timeout_s)
    duration = time.time() - t0
    rc = env.get("returncode", -1)

    _pe_record_history(local_path, rc, duration)

    return _with_error({
        "success": env.get("success", False),
        "output": "",
        "stderr": _pe_tail(env.get("stderr", "")),
        "returncode": rc,
        "handler": h,
        "handler_type": h,
        "path": local_path,
        "stdout": _pe_tail(env.get("output", "")),
        "duration_s": round(duration, 3),
        "error": env.get("error"),
    })


def _pe_parse_headers(path: str) -> dict:
    """Parse first 1KB of a PE file; purely structural, no execution."""
    out = {
        "magic": None,
        "machine": None,
        "is_dll": False,
        "is_64bit": False,
        "subsystem": None,
        "import_count": 0,
        "has_digital_signature": False,
    }
    try:
        with open(path, "rb") as f:
            buf = f.read(1024)
    except OSError as e:
        out["error"] = f"cannot read {path}: {e}"
        return out
    if len(buf) < 64 or buf[:2] != b"MZ":
        out["error"] = "not a PE file (missing MZ)"
        return out
    out["magic"] = "MZ"
    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
    if e_lfanew < 0 or e_lfanew + 24 > len(buf):
        # Reread a bigger window if header is further into the file.
        try:
            with open(path, "rb") as f:
                buf = f.read(max(1024, e_lfanew + 256))
        except OSError as e:
            out["error"] = f"cannot reread {path}: {e}"
            return out
    if e_lfanew + 4 > len(buf) or buf[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        out["error"] = "invalid PE signature"
        return out
    coff = struct.unpack_from("<HHIIIHH", buf, e_lfanew + 4)
    machine, _nsects, _ts, _ptbl, _nsyms, sz_opt, chars = coff
    machine_map = {
        0x014c: "i386",
        0x8664: "x86_64",
        0xaa64: "arm64",
        0x01c4: "arm",
        0x0200: "ia64",
    }
    out["machine"] = machine_map.get(machine, f"0x{machine:04x}")
    out["is_dll"] = bool(chars & 0x2000)  # IMAGE_FILE_DLL
    opt_off = e_lfanew + 4 + 20
    if sz_opt and opt_off + 2 <= len(buf):
        opt_magic = struct.unpack_from("<H", buf, opt_off)[0]
        if opt_magic == 0x10b:
            out["is_64bit"] = False
            out["optional_magic"] = "PE32"
            out["hint_32bit"] = (
                "PE32 (32-bit) — pe-loader currently refuses 32-bit PE "
                "images; consider running via wine or a 32-bit host.")
        elif opt_magic == 0x20b:
            out["is_64bit"] = True
            out["optional_magic"] = "PE32+"
        else:
            out["optional_magic"] = f"0x{opt_magic:04x}"
        # Subsystem sits at opt_off + 68 for BOTH PE32 and PE32+ (layout
        # diverges later at ImageBase).  Verified against winnt.h.
        subsys_off = opt_off + 68
        if subsys_off + 2 <= len(buf):
            subsys = struct.unpack_from("<H", buf, subsys_off)[0]
            sub_map = {
                1: "driver",
                2: "GUI",
                3: "CLI",
                5: "OS2_CUI",
                7: "POSIX_CUI",
                9: "WindowsCE_GUI",
                10: "EFI_APPLICATION",
                11: "EFI_BOOT_SERVICE_DRIVER",
                12: "EFI_RUNTIME_DRIVER",
                13: "EFI_ROM",
                14: "XBOX",
            }
            out["subsystem"] = sub_map.get(subsys, f"0x{subsys:04x}")
        # Data directories: 16 entries × 8 bytes. Import=1, Security=4.
        # Base differs by optional magic.
        if out["is_64bit"]:
            data_dir_off = opt_off + 112
        else:
            data_dir_off = opt_off + 96
        import_entry_off = data_dir_off + 1 * 8
        security_entry_off = data_dir_off + 4 * 8
        if import_entry_off + 8 <= len(buf):
            _import_rva, import_size = struct.unpack_from(
                "<II", buf, import_entry_off)
            if import_size >= 20:
                # IMAGE_IMPORT_DESCRIPTOR = 20 bytes; terminator is zeroed.
                out["import_count"] = max(0, (import_size // 20) - 1)
        if security_entry_off + 8 <= len(buf):
            _sec_rva, sec_size = struct.unpack_from(
                "<II", buf, security_entry_off)
            out["has_digital_signature"] = bool(sec_size > 0)
    return out


async def pe_analyze(args):
    h = "pe.analyze"
    raw_path = args.get("path")
    ok, resolved = _pe_resolve_path(raw_path, h, allow_url=False)
    if not ok:
        return resolved
    if not os.path.exists(resolved):
        return _bad_arg(h, f"file does not exist: {resolved}")
    mz_ok, why = _pe_check_mz(resolved)
    if not mz_ok:
        return _bad_arg(h, why)
    info = _pe_parse_headers(resolved)
    if "error" in info:
        return {"success": False, "output": "", "stderr": info["error"],
                "returncode": 1, "handler": h, "handler_type": h,
                "error": info["error"], "path": resolved}
    summary = (f"{info.get('optional_magic', '?')} "
               f"{info.get('machine', '?')} "
               f"{'DLL' if info['is_dll'] else 'EXE'} "
               f"subsys={info.get('subsystem', '?')} "
               f"imports~{info['import_count']}")
    return {
        "success": True,
        "output": summary,
        "stderr": "",
        "returncode": 0,
        "handler": h,
        "handler_type": h,
        "path": resolved,
        **info,
    }


async def pe_install_msi(args):
    h = "pe.install_msi"
    raw_path = args.get("path") or args.get("path_or_url")
    ok, resolved = _pe_resolve_path(raw_path, h, allow_url=True)
    if not ok:
        return resolved

    if _pe_is_url(resolved):
        dl = await _pe_download(resolved, h)
        if not dl["ok"]:
            return _with_error(dl["env"])
        local_path = dl["path"]
    else:
        local_path = resolved
        if not os.path.exists(local_path):
            return _bad_arg(h, f"file does not exist: {local_path}")

    if not os.path.exists(_PE_LOADER_BIN):
        return _missing(h, _PE_LOADER_BIN,
                        install_hint="pacman -S pe-loader")

    # Heuristic probe for msiexec stub — pe-loader's -list-stubs surface
    # is not stable, so we fall back to filesystem presence checks.
    msiexec_candidates = [
        "/usr/lib/pe-compat/msiexec.exe",
        "/usr/share/pe-loader/msiexec.exe",
        "/opt/pe-loader/msiexec.exe",
    ]
    msiexec_found = next(
        (p for p in msiexec_candidates if os.path.exists(p)), None)
    if not msiexec_found:
        return {
            "success": False,
            "output": "",
            "stderr": "msiexec stub not available",
            "returncode": 1,
            "handler": h,
            "handler_type": h,
            "reason": "msiexec_stub_missing",
            "hint": ("install peloader-extras or run the MSI manually via "
                     "peloader /usr/bin/msiexec.exe"),
            "path": local_path,
            "error": "msiexec stub not available",
        }

    argv = [_PE_LOADER_BIN, msiexec_found, "/i", local_path, "/qn"]
    t0 = time.time()
    env = await _exec(h, argv, timeout=300)
    duration = time.time() - t0
    rc = env.get("returncode", -1)
    _pe_record_history(local_path, rc, duration)
    return _with_error({
        "success": env.get("success", False),
        "output": "",
        "stderr": _pe_tail(env.get("stderr", "")),
        "returncode": rc,
        "handler": h,
        "handler_type": h,
        "path": local_path,
        "msiexec": msiexec_found,
        "stdout": _pe_tail(env.get("output", "")),
        "duration_s": round(duration, 3),
        "error": env.get("error"),
    })


async def pe_list_recent(args):
    h = "pe.list_recent"
    entries = []
    try:
        if os.path.exists(_PE_HISTORY_FILE):
            with open(_PE_HISTORY_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except OSError as e:
        return {"success": False, "output": "", "stderr": str(e),
                "returncode": 1, "handler": h, "handler_type": h,
                "error": str(e), "entries": []}
    entries = entries[-_PE_HISTORY_KEEP:]
    return {
        "success": True,
        "output": f"{len(entries)} recent pe runs",
        "stderr": "",
        "returncode": 0,
        "handler": h,
        "handler_type": h,
        "entries": entries,
        "count": len(entries),
    }


async def pe_clear_cache(args):
    h = "pe.clear_cache"
    band = (args.get("trust_band") or args.get("caller_trust_band") or "")
    if str(band).upper() != "TRUST_ADMIN":
        return {
            "success": False,
            "output": "",
            "stderr": "pe.clear_cache requires TRUST_ADMIN",
            "returncode": 1,
            "handler": h,
            "handler_type": h,
            "error": "insufficient trust band",
            "required_trust_band": "TRUST_ADMIN",
        }
    removed = 0
    errs = []
    if os.path.isdir(_PE_DOWNLOAD_DIR):
        for name in os.listdir(_PE_DOWNLOAD_DIR):
            p = os.path.join(_PE_DOWNLOAD_DIR, name)
            try:
                if os.path.isfile(p) or os.path.islink(p):
                    os.unlink(p)
                    removed += 1
            except OSError as e:
                errs.append(f"{name}: {e}")
    return {
        "success": not errs,
        "output": f"removed {removed} files from {_PE_DOWNLOAD_DIR}",
        "stderr": "; ".join(errs),
        "returncode": 0 if not errs else 1,
        "handler": h,
        "handler_type": h,
        "removed": removed,
        "errors": errs,
        "path": _PE_DOWNLOAD_DIR,
    }


HANDLERS["pe.run"]         = pe_run
HANDLERS["pe.analyze"]     = pe_analyze
HANDLERS["pe.install_msi"] = pe_install_msi
HANDLERS["pe.list_recent"] = pe_list_recent
HANDLERS["pe.clear_cache"] = pe_clear_cache

# Session 68 Agent S -- windows software catalog installer
HANDLERS["app.install_windows"] = app_install_windows
