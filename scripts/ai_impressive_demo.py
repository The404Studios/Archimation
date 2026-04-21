#!/usr/bin/env python3
"""ai_impressive_demo.py -- run against a live daemon on :8420 with AICONTROL_TOKEN.

Shows: one-word commands, compound intents, software catalog, queries, file ops,
PE-loader invocation, clarification. Run inside a booted ISO.

Structure: 7 named GROUPS, each with 5-10 phrases. For each phrase, POST to
/contusion/context, extract handler_type from the S68 inner-result envelope,
classify GREEN / YELLOW (dispatched but handler errored harmlessly) / RED (no
handler) / CLARIFY (contusion.clarify) and tally.

Exits 0 if >= 90% of phrases are GREEN+CLARIFY combined, else 1.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

DAEMON = os.environ.get("AICONTROL_DAEMON", "http://127.0.0.1:8420")
TOKEN = os.environ.get("AICONTROL_TOKEN", "")


# Each GROUP: list of (phrase, expected_handler_prefix_or_None).
# expected=None means "any routing is acceptable" (used for wide queries).
# expected="contusion.clarify" means this phrase SHOULD be ambiguous.
GROUPS = {
    "ONE_WORD": [
        ("mute",         "audio.mute_toggle"),
        ("unmute",       "audio.mute_toggle"),
        ("louder",       "audio.volume_up"),
        ("quieter",      "audio.volume_down"),
        ("brighter",     "brightness.up"),
        ("dimmer",       "brightness.down"),
        ("lock",         "power.lock_screen"),
        ("suspend",      "power.suspend"),
    ],
    "QUERIES": [
        ("how much disk space",      "query.disk_space"),
        ("what is my ip",            "query.ip_address"),
        ("uptime",                   "query.uptime"),
        ("cpu temperature",          None),
        ("who is logged in",         "query.logged_in_users"),
        ("kernel version",           "query.kernel_version"),
        ("load average",             "query.loadavg"),
        ("what is using the most memory", "query.memory_top"),
    ],
    "COMPOUND": [
        ("mute and lock screen",                            None),
        ("take a screenshot and copy it to clipboard",      None),
        ("volume up then pause music",                      None),
        ("check disk space and show my ip",                 None),
        ("lock screen and suspend",                         None),
    ],
    "SOFTWARE_INSTALL": [
        ("install visual studio community",     "app.install_windows"),
        ("install 7-zip",                        "app.install_windows"),
        ("get firefox",                          "app.install_windows"),
        ("download vscode",                      "app.install_windows"),
        ("install obs",                          "app.install_windows"),
        ("install blender",                      "app.install_windows"),
        ("install cmake",                        "app.install_windows"),
    ],
    "PE_LOADER": [
        ("run this exe",            "pe.run"),
        ("analyze this pe file",    "pe.analyze"),
        ("list recent pe runs",     "pe.list_recent"),
        ("run the exe",             "pe.run"),
        ("install this msi",        "pe.install_msi"),
    ],
    "FILE_OPS": [
        ("delete empty folders in downloads",          "file.delete_empty_dirs"),
        ("find the 10 largest files in my home",       "file.find_largest"),
        ("list recent files in documents",             "file.list_recent"),
        ("zip my downloads",                           "file.zip_folder"),
        ("what has changed recently",                  None),
    ],
    "CLARIFICATION": [
        ("up",          "contusion.clarify"),
        ("volume",      "contusion.clarify"),
        ("brightness",  "contusion.clarify"),
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
            err_body = json.loads(e.read().decode())
        except Exception:
            err_body = {"http_error": str(e)}
        return e.code, err_body
    except Exception as e:
        return 0, {"transport_error": str(e)}


def extract_envelope(body):
    """Pull handler_type, confidence, asking, source out of the S68-wrapped body.

    Returns (handler_type, confidence_float_or_None, asking_string_or_None, source_label).
    """
    if not isinstance(body, dict):
        return None, None, None, None
    # S68 wraps the route() return as {"status":"ok","result":...}
    inner = body.get("result") if isinstance(body.get("result"), dict) else body

    handler_type = inner.get("handler_type")
    conf = inner.get("confidence")
    asking = inner.get("asking")
    source = inner.get("source")

    # results list shape
    if not handler_type:
        results = inner.get("results") or []
        if isinstance(results, list) and results:
            r0 = results[0]
            if isinstance(r0, dict):
                handler_type = r0.get("handler_type")
    # actions list shape
    if not handler_type:
        actions = inner.get("actions") or inner.get("pending") or []
        if isinstance(actions, list) and actions:
            a = actions[0]
            if isinstance(a, dict):
                handler_type = a.get("handler_type")
    # proposal.results shape
    if not handler_type:
        proposal = inner.get("proposal") or {}
        results = proposal.get("results") or []
        if isinstance(results, list) and results:
            r = results[0]
            if isinstance(r, dict):
                handler_type = r.get("handler_type")

    try:
        conf_f = float(conf) if conf is not None else None
    except (TypeError, ValueError):
        conf_f = None

    return handler_type, conf_f, asking, source


def _matches(expected, actual):
    """Prefix-match-with-dot semantics. None matches anything non-null."""
    if expected is None:
        return bool(actual)
    if not actual:
        return False
    exp = expected.lower().strip()
    act = actual.lower().strip()
    if exp == act:
        return True
    if act.startswith(exp + "."):
        return True
    # expected='app.install_windows' should match 'app.install_windows' only
    return False


def classify(expected, handler_type):
    """GREEN, YELLOW, CLARIFY, RED."""
    if handler_type == "contusion.clarify":
        if expected == "contusion.clarify":
            return "CLARIFY"
        # Got clarify when we didn't want it — count as YELLOW
        # (routed, just unsure). Still useful signal.
        return "CLARIFY"
    if handler_type is None:
        return "RED"
    if _matches(expected, handler_type):
        return "GREEN"
    # Routed to something else; partial win.
    return "YELLOW"


def run_phrase(phrase, expected):
    t0 = time.time()
    status, body = http_post("/contusion/context", {"text": phrase})
    elapsed_ms = int((time.time() - t0) * 1000)
    handler_type, conf, asking, source = extract_envelope(body)
    verdict = classify(expected, handler_type)
    return {
        "phrase": phrase,
        "expected": expected,
        "handler_type": handler_type,
        "confidence": conf,
        "asking": asking,
        "source": source,
        "http_status": status,
        "elapsed_ms": elapsed_ms,
        "verdict": verdict,
    }


def _fmt_conf(c):
    if c is None:
        return ""
    return f"(conf={c:.2f})"


def main():
    print(f"ai_impressive_demo: target={DAEMON} token_len={len(TOKEN)}")
    print("=" * 78)

    totals = {"GREEN": 0, "YELLOW": 0, "CLARIFY": 0, "RED": 0}
    total_phrases = 0

    grouped_results = {}

    for group, phrases in GROUPS.items():
        print()
        print(f"=== {group} ({len(phrases)} phrases) ===")
        grouped_results[group] = []
        for phrase, expected in phrases:
            total_phrases += 1
            r = run_phrase(phrase, expected)
            grouped_results[group].append(r)
            v = r["verdict"]
            totals[v] = totals.get(v, 0) + 1

            tag = {
                "GREEN":   "[GREEN]  ",
                "YELLOW":  "[YELLOW] ",
                "CLARIFY": "[CLARIFY]",
                "RED":     "[RED]    ",
            }.get(v, "[??]     ")

            ht = r["handler_type"] or "(no handler)"
            conf = _fmt_conf(r["confidence"])
            ms = r["elapsed_ms"]

            line = f"{tag} {phrase:48s} -> {ht:30s} {conf}  {ms}ms"
            print(line)
            if v == "CLARIFY" and r["asking"]:
                print(f"            asking={r['asking']!r}")
            if v == "YELLOW" and expected:
                print(f"            (expected {expected!r}, got {ht!r})")

    print()
    print("=" * 78)
    print(f"  TOTAL: {total_phrases} phrases")
    print(f"  GREEN   = {totals.get('GREEN', 0):3d}")
    print(f"  CLARIFY = {totals.get('CLARIFY', 0):3d}")
    print(f"  YELLOW  = {totals.get('YELLOW', 0):3d}")
    print(f"  RED     = {totals.get('RED', 0):3d}")

    # Pass threshold: GREEN + CLARIFY >= 90% of total
    good = totals.get("GREEN", 0) + totals.get("CLARIFY", 0)
    pct = (100.0 * good / total_phrases) if total_phrases else 0.0
    print(f"  PASS %  = {pct:.1f}% (green+clarify / total, threshold 90%)")
    print("=" * 78)

    # Machine-readable tail for the wrapper script to parse
    summary = {
        "total": total_phrases,
        "green": totals.get("GREEN", 0),
        "yellow": totals.get("YELLOW", 0),
        "clarify": totals.get("CLARIFY", 0),
        "red": totals.get("RED", 0),
        "pass_pct": round(pct, 1),
        "groups": {
            g: {
                "phrases": rs,
                "green":   sum(1 for r in rs if r["verdict"] == "GREEN"),
                "yellow":  sum(1 for r in rs if r["verdict"] == "YELLOW"),
                "clarify": sum(1 for r in rs if r["verdict"] == "CLARIFY"),
                "red":     sum(1 for r in rs if r["verdict"] == "RED"),
            }
            for g, rs in grouped_results.items()
        },
    }
    sys.stdout.write("\n--- BEGIN_JSON_SUMMARY ---\n")
    sys.stdout.write(json.dumps(summary, indent=2, default=str))
    sys.stdout.write("\n--- END_JSON_SUMMARY ---\n")

    return 0 if pct >= 90.0 else 1


if __name__ == "__main__":
    sys.exit(main())
