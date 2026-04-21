#!/usr/bin/env python3
"""sweep_handlers_with_nl.py — extends sweep_handlers.py with two extra checks:

1. BINARIES — calls `shutil.which()` on each binary the handlers depend on.
   Reports which are now present (and at what path).

2. NL_COMMANDS — exercises ~30 representative natural-language commands via
   /contusion/context using the bearer token, capturing handler_type and
   success.

Run on the booted ISO as root.  Emits one JSON blob to stdout.
"""

import asyncio
import json
import os
import shutil
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, "/usr/lib/ai-control-daemon")

DAEMON = "http://127.0.0.1:8420"
TOKEN = os.environ.get("AICONTROL_TOKEN", "")

BINARIES = [
    # name -> arch package
    ("playerctl", "playerctl"),
    ("xset", "xorg-xset"),
    ("bluetoothctl", "bluez-utils"),
    ("wmctrl", "wmctrl"),
    ("xdotool", "xdotool"),
    ("copyq", "copyq"),
    ("redshift", "redshift"),
    ("gammastep", "gammastep"),
    ("notify-send", "libnotify"),
    ("brightnessctl", "brightnessctl"),
    ("wpctl", "wireplumber"),
    ("pactl", "pulseaudio-utils"),
    ("grim", "grim"),
    ("slurp", "slurp"),
    ("scrot", "scrot"),
    ("npm", "npm"),
    ("node", "nodejs"),
    ("nvidia-smi", "nvidia-utils"),
    ("radeontop", "radeontop"),
    ("sensors", "lm_sensors"),
    ("acpi", "acpi"),
    ("xrandr", "xorg-xrandr"),
]

# Representative NL commands the user might type into ai CLI.
# (phrase, expected_handler_substring) — we verify routing landed somewhere
# sensible and that dispatch succeeded structurally.
NL_COMMANDS = [
    ("list scripts",                        "script.list"),
    ("show system info",                    "script.run"),
    ("run hello",                           "script.run"),
    ("is claude installed",                 "app.claude_status"),
    ("set up claude workspace",             "app.claude_workspace_init"),
    ("what is my brightness",               "brightness.get"),
    ("turn brightness up",                  "brightness.up"),
    ("turn brightness down",                "brightness.down"),
    ("max brightness",                      "brightness.max"),
    ("auto brightness",                     "brightness.auto"),
    ("volume up",                           "audio.volume_up"),
    ("volume down",                         "audio.volume_down"),
    ("mute",                                "audio.mute_toggle"),
    ("list audio sinks",                    "audio.sink_list"),
    ("play music",                          "media.play"),
    ("pause music",                         "media.pause"),
    ("next song",                           "media.next"),
    ("media status",                        "media.status"),
    ("list media players",                  "media.list_players"),
    ("take a screenshot",                   "system.screenshot_full"),
    ("notify hello world",                  "system.notify"),
    ("show bluetooth devices",              "monitoring.bt_devices"),
    ("battery percent",                     "monitoring.battery_percent"),
    ("cpu frequency",                       "monitoring.cpu_freq"),
    ("wifi signal",                         "monitoring.wifi_signal"),
    ("list services",                       "service.list"),
    ("list drivers",                        "driver.list"),
    ("list windows",                        "window.list"),
    ("list workspaces",                     "workspace.list"),
    ("list running games",                  "game.list"),
    ("turn off display",                    "power.screen_off"),
    ("lock screen",                         "power.lock_screen"),
    ("night light on",                      "system.night_light"),
]


def _handler_matches(expected, actual):
    """
    Exact match, with optional tolerance for namespace prefixes:
      expected='audio.mute_toggle' matches 'audio.mute_toggle'
      expected='system' matches 'system.screenshot_full' (namespace query)
      does NOT match 'audio.mute' -> 'audio.mute_toggle'
    """
    if not actual:
        return False
    exp = expected.lower().strip()
    act = actual.lower().strip()
    if exp == act:
        return True
    if act.startswith(exp + "."):
        return True
    return False


def http_post(path, body, timeout=10):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        DAEMON + path,
        data=data,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TOKEN}" if TOKEN else "",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
        except Exception:
            body = {"http_error": str(e)}
        return e.code, body
    except Exception as e:
        return 0, {"transport_error": str(e)}


def probe_binaries():
    out = []
    for name, pkg in BINARIES:
        path = shutil.which(name)
        out.append({"binary": name, "package": pkg, "path": path, "present": path is not None})
    return out


def probe_nl_commands():
    out = []
    for phrase, expected in NL_COMMANDS:
        t0 = time.time()
        status, body = http_post("/contusion/context", {"text": phrase})
        elapsed_ms = int((time.time() - t0) * 1000)

        # Pull handler_type out of the response shape
        handler_type = None
        success = None
        if isinstance(body, dict):
            # /contusion/context returns various shapes
            ht = body.get("handler_type")
            if ht:
                handler_type = ht
            else:
                # Search nested
                actions = body.get("actions") or body.get("pending") or []
                if actions and isinstance(actions, list):
                    a = actions[0]
                    if isinstance(a, dict):
                        handler_type = a.get("handler_type")
                if not handler_type:
                    proposal = body.get("proposal") or {}
                    results = proposal.get("results") or []
                    if results and isinstance(results, list):
                        r = results[0]
                        if isinstance(r, dict):
                            handler_type = r.get("handler_type") or (
                                r.get("plan", {}).get("handler_type") if isinstance(r.get("plan"), dict) else None
                            )
                            success = r.get("success")

        matched = _handler_matches(expected, handler_type)
        out.append({
            "phrase": phrase,
            "expected_substr": expected,
            "actual_handler": handler_type,
            "matched": bool(matched),
            "http_status": status,
            "success": success,
            "elapsed_ms": elapsed_ms,
        })
    return out


async def main():
    bin_results = probe_binaries()
    nl_results = probe_nl_commands()

    bin_present = sum(1 for b in bin_results if b["present"])
    bin_total = len(bin_results)
    nl_matched = sum(1 for n in nl_results if n["matched"])
    nl_total = len(nl_results)

    out = {
        "summary": {
            "binaries_present": f"{bin_present}/{bin_total}",
            "nl_routing_matched": f"{nl_matched}/{nl_total}",
        },
        "binaries": bin_results,
        "nl_commands": nl_results,
    }
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
