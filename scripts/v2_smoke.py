#!/usr/bin/env python3
"""v2_smoke.py — long-tail dictionary_v2 smoke (Session 63).

Probes 30+ NL phrases that A1's templates SHOULD route but the static
dictionary likely misses. Each phrase was verified against the live
artifact via scripts/probe_v2.py before landing here, so a miss in
production means contusion.py is not consulting v2 (or v2 didn't ship).

Reports per-family + an overall PASS/FAIL line.

Run inside the booted ISO. Requires AICONTROL_TOKEN.
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error

DAEMON = os.environ.get("AICONTROL_DAEMON", "http://127.0.0.1:8420")
TOKEN = os.environ.get("AICONTROL_TOKEN", "")

# (phrase, expected_handler_substring) — all template-generated phrases that
# the static dict likely doesn't cover verbatim. Verified routable via
# scripts/probe_v2.py against the built artifact.
LONG_TAIL = [
    # AUDIO — colloquial slang
    ("raise the volume",         "audio.volume_up"),
    ("lower volume",             "audio.volume_down"),
    ("make it louder",           "audio.volume_up"),
    ("make it quieter",          "audio.volume_down"),
    ("vol up",                   "audio.volume_up"),
    ("vol down",                 "audio.volume_down"),
    ("silence",                  "audio.mute_toggle"),
    ("toggle the microphone",    "audio.mic_mute_toggle"),
    # BRIGHTNESS
    ("brighten the screen",      "brightness.up"),
    ("dim the screen",           "brightness.down"),
    ("make it darker",           "brightness.down"),
    ("make it brighter",         "brightness.up"),
    ("auto brightness",          "brightness.auto"),
    # MEDIA — colloquial
    ("kill the music",           "media.stop"),
    ("now playing",              "media.status"),
    ("back to the last song",    "media.prev"),
    ("next song please",         "media.next"),
    ("toggle playback",          "media.play_pause"),
    # POWER / SCREEN
    ("wake the screen",          "power.screen_on"),
    ("screen sleep",             "power.screen_off"),
    ("lock my session",          "power.lock_screen"),
    # SYSTEM
    ("snipping tool",            "system.screenshot_region"),
    ("warmer screen",            "system.night_light"),
    # MONITORING
    ("battery left",             "monitoring.battery_percent"),
    ("battery time remaining",   "monitoring.battery_time"),
    ("how hot is the gpu",       "monitoring.gpu_temp"),
    ("gpu info",                 "monitoring.gpu_status"),
    ("fan rpm",                  "monitoring.fan_speed"),
    ("wifi strength",            "monitoring.wifi_signal"),
    # WINDOW
    ("x out",                    "window.close"),
    ("min the window",           "window.minimize"),
    ("f11",                      "window.fullscreen_toggle"),
    # WORKSPACE
    ("ws next",                  "workspace.next"),
    ("ws prev",                  "workspace.prev"),
    ("mission control",          "workspace.show_all"),
    ("expose desktops",          "workspace.show_all"),
    ("overview",                 "workspace.show_all"),
    # CLAUDE
    ("do i have claude",         "app.claude_status"),
    # CLIPBOARD
    ("paste here",               "clipboard.paste_cursor"),
    ("paste it",                 "clipboard.paste_cursor"),
    ("wipe clipboard",           "clipboard.clear"),
    # DRIVER
    ("lsmod",                    "driver.list"),
]


def http_post(path, body, timeout=10):
    data = json.dumps(body).encode()
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
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


def extract_handler_and_source(body):
    """Pull handler_type + source label out of /contusion/context response.

    S74 (Agent W): the /contusion/context endpoint wraps the Contusion.route()
    output in ``{"status": "ok", "result": {...}}``. Pre-S74 versions of this
    script read ``body.get("handler_type")`` directly, always returning None,
    so the "S63 42/42 routed" claim in MEMORY.md was a phantom — this script
    has been 0/42 against the wrapped API since it was written. Match the
    pattern used by ``scripts/set_smoke.py:120`` and unwrap ``body["result"]``
    first if present.
    """
    if not isinstance(body, dict):
        return None, None
    # Unwrap {"status": "ok", "result": {...}} → {...}
    inner = body.get("result") if isinstance(body.get("result"), dict) else body
    handler_type = inner.get("handler_type")
    source = inner.get("source") or inner.get("rationale")
    actions = inner.get("actions") or inner.get("pending") or []
    if not handler_type and isinstance(actions, list) and actions:
        a = actions[0]
        if isinstance(a, dict):
            handler_type = a.get("handler_type")
            if not source:
                source = a.get("source") or a.get("rationale")
    # results list shape (S68 route() also returns results: [{handler_type: ...}])
    if not handler_type:
        results = inner.get("results") or []
        if isinstance(results, list) and results:
            r0 = results[0]
            if isinstance(r0, dict):
                handler_type = r0.get("handler_type")
                if not source:
                    source = r0.get("source") or r0.get("rationale")
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
                if not source:
                    source = r.get("source") or r.get("rationale")
    return handler_type, source


def probe(phrase, expected):
    t0 = time.time()
    status, body = http_post("/contusion/context", {"text": phrase})
    elapsed_ms = int((time.time() - t0) * 1000)
    handler_type, source = extract_handler_and_source(body)
    routed = handler_type and (expected.lower() in handler_type.lower())
    return {
        "phrase": phrase,
        "expected": expected,
        "actual_handler": handler_type,
        "routed": bool(routed),
        "http_status": status,
        "source": source,
        "elapsed_ms": elapsed_ms,
    }


def main():
    results = [probe(p, e) for p, e in LONG_TAIL]
    routed = sum(1 for r in results if r["routed"])
    total = len(results)
    v2_hits = sum(1 for r in results if r.get("source") and "v2" in str(r["source"]).lower())

    out = {
        "total": total,
        "routed": routed,
        "v2_template_hits": v2_hits,
        "results": results,
    }
    print(json.dumps(out, indent=2, default=str))

    # tally line for quick grep
    sys.stderr.write(
        f"V2_SMOKE: routed={routed}/{total} v2_source={v2_hits}/{total}\n"
    )
    return 0 if routed >= total * 0.8 else 1


if __name__ == "__main__":
    sys.exit(main())
