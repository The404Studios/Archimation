#!/usr/bin/env python3
"""set_smoke.py — set-organized smoke test.

Dispatches NL phrases grouped into 13 named capability SETS.  Each set is
GREEN (all phrases route + dispatch with success), YELLOW (mixed), or RED
(none route).  Per-set failure detail is printed for the YELLOW/RED ones.

Run inside the booted ISO.  Requires AICONTROL_TOKEN env var.
"""

import asyncio
import json
import os
import shutil
import sys
import time
import urllib.request
import urllib.error

DAEMON = os.environ.get("AICONTROL_DAEMON", "http://127.0.0.1:8420")
TOKEN = os.environ.get("AICONTROL_TOKEN", "")

# Each set: list of (phrase, expected_handler_substring).
# A set is GREEN if every phrase routes correctly AND dispatches without
# error (HTTP 200 + handler_type in expected substring).
SETS = {
    "BRIGHTNESS": [
        ("turn brightness up",   "brightness.up"),
        ("turn brightness down", "brightness.down"),
        ("what is my brightness", "brightness.get"),
        ("max brightness",       "brightness.max"),
        ("auto brightness",      "brightness.auto"),
    ],
    "AUDIO": [
        ("volume up",            "audio.volume_up"),
        ("volume down",          "audio.volume_down"),
        ("mute",                 "audio.mute_toggle"),
        ("list audio sinks",     "audio.sink_list"),
    ],
    "MEDIA": [
        ("play music",           "media.play"),
        ("pause music",          "media.pause"),
        ("next song",            "media.next"),
        ("media status",         "media.status"),
        ("list media players",   "media.list_players"),
    ],
    "POWER": [
        ("lock screen",          "power.lock_screen"),
        ("turn off display",     "power.screen_off"),
    ],
    "SYSTEM": [
        ("take a screenshot",    "system.screenshot_full"),
        ("notify hello world",   "system.notify"),
        ("night light on",       "system.night_light"),
    ],
    "MONITORING": [
        ("show bluetooth devices", "monitoring.bt_devices"),
        ("battery percent",        "monitoring.battery_percent"),
        ("cpu frequency",          "monitoring.cpu_freq"),
        ("wifi signal",            "monitoring.wifi_signal"),
    ],
    "WINDOW": [
        ("list windows",         "window.list"),
    ],
    "WORKSPACE": [
        ("list workspaces",      "workspace.list"),
    ],
    "SERVICE": [
        ("list services",        "service.list"),
    ],
    "DRIVER": [
        ("list drivers",         "driver.list"),
    ],
    "SCRIPT": [
        ("list scripts",         "script.list"),
        ("run hello",            "script.run"),
        ("show system info",     "script.run"),
    ],
    "APP_CLAUDE": [
        ("is claude installed",      "app.claude_status"),
        ("set up claude workspace",  "app.claude_workspace_init"),
    ],
    "GAME": [
        ("list running games",   "game.list"),
    ],
}


def http_post(path, body, timeout=10):
    data = json.dumps(body).encode()
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    req = urllib.request.Request(DAEMON + path, data=data, headers=headers)
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


def extract_handler_and_success(body):
    """Pull handler_type + success flag out of /contusion/context response."""
    handler_type = None
    success = None
    if not isinstance(body, dict):
        return None, None
    # S68: the endpoint wraps the route() return in {"status":"ok","result":...}
    # so the handler_type we want lives one level deeper. Try both shapes so
    # this works whether or not the envelope is present.
    inner = body.get("result") if isinstance(body.get("result"), dict) else body
    if inner.get("handler_type"):
        handler_type = inner["handler_type"]
    if "success" in inner:
        success = inner["success"]
    # actions list shape
    actions = inner.get("actions") or inner.get("pending") or []
    if not handler_type and isinstance(actions, list) and actions:
        a = actions[0]
        if isinstance(a, dict):
            handler_type = a.get("handler_type")
    # results list shape (S68 route() also returns results: [{handler_type: ...}])
    if not handler_type:
        results = inner.get("results") or []
        if isinstance(results, list) and results:
            r0 = results[0]
            if isinstance(r0, dict):
                handler_type = r0.get("handler_type")
    # proposal.results shape (cortex)
    if not handler_type:
        proposal = inner.get("proposal") or {}
        results = proposal.get("results") or []
        if isinstance(results, list) and results:
            r = results[0]
            if isinstance(r, dict):
                handler_type = r.get("handler_type") or (
                    r.get("plan", {}).get("handler_type")
                    if isinstance(r.get("plan"), dict) else None
                )
                if success is None:
                    success = r.get("success")
    return handler_type, success


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
    # namespace match: expected is a prefix and what follows in actual starts with a dot
    if act.startswith(exp + "."):
        return True
    return False


def probe_phrase(phrase, expected):
    t0 = time.time()
    status, body = http_post("/contusion/context", {"text": phrase})
    elapsed_ms = int((time.time() - t0) * 1000)
    handler_type, success = extract_handler_and_success(body)
    routed = _handler_matches(expected, handler_type)
    return {
        "phrase": phrase,
        "expected": expected,
        "actual_handler": handler_type,
        "routed": bool(routed),
        "http_status": status,
        "success": success,
        "elapsed_ms": elapsed_ms,
    }


def classify_set(results):
    """GREEN = all routed, YELLOW = some routed, RED = none routed."""
    routed = sum(1 for r in results if r["routed"])
    total = len(results)
    if routed == total:
        return "GREEN"
    if routed == 0:
        return "RED"
    return "YELLOW"


async def main():
    out = {"sets": {}, "summary": {}}
    set_status = {}
    for set_name, phrases in SETS.items():
        results = [probe_phrase(p, e) for p, e in phrases]
        status = classify_set(results)
        set_status[set_name] = status
        routed = sum(1 for r in results if r["routed"])
        total = len(results)
        out["sets"][set_name] = {
            "status": status,
            "routed": f"{routed}/{total}",
            "phrases": results,
        }

    out["summary"] = {
        "total_sets": len(SETS),
        "GREEN": sum(1 for s in set_status.values() if s == "GREEN"),
        "YELLOW": sum(1 for s in set_status.values() if s == "YELLOW"),
        "RED": sum(1 for s in set_status.values() if s == "RED"),
        "total_phrases": sum(len(p) for p in SETS.values()),
        "phrases_routed": sum(
            sum(1 for r in s["phrases"] if r["routed"])
            for s in out["sets"].values()
        ),
    }

    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
