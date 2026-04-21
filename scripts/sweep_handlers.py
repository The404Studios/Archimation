#!/usr/bin/env python3
"""sweep_handlers.py — exhaustive AI-handler dispatch sweep.

Imports the live contusion_handlers.HANDLERS registry and dispatches every
non-destructive handler with empty args, tallying outcomes per family.

Run on the booted ISO as root (or via sudo).  Emits a single JSON blob to
stdout so the harness can parse it deterministically.
"""

import asyncio
import sys
import json
import time

sys.path.insert(0, "/usr/lib/ai-control-daemon")

# Handlers we DO NOT want to fire even once during a sweep.
DESTRUCTIVE = {
    # power: would reboot/poweroff the VM
    "power.shutdown", "power.reboot", "power.hibernate",
    "power.suspend", "power.logout",
    # service: would break the running daemon if it stops itself
    "service.stop", "service.restart", "service.reload", "service.disable",
    # driver: unloading is rarely safe to blind-fire
    "driver.unload",
    # game.kill: would SIGKILL processes
    "game.kill",
    # workspace: don't delete the live workspace
    "workspace.delete_current",
    # app.install_*: would touch the network and pacman
    "app.install_steam", "app.install_lutris", "app.install_heroic",
    "app.install_proton", "app.install_claude",
    # audio.restart: would kill pipewire mid-test
    "audio.restart",
    # perf.*: changes power profile / loads gamescope / etc — too disruptive
    "perf.gamescope_off", "perf.gamescope_on",
    "perf.lowlatency_off", "perf.lowlatency_on", "perf.dxvk_clear",
    # system.record: would start a screen recording
    "system.record_start", "system.record_stop",
    # legacy.shell_exec: arbitrary shell — never blind-fire
    "legacy.shell_exec",
}


async def call(fn, args, timeout=8.0):
    try:
        r = await asyncio.wait_for(fn(args), timeout=timeout)
        return ("OK", r)
    except asyncio.TimeoutError:
        return ("TIMEOUT", None)
    except Exception as e:
        return ("EXCEPT", f"{type(e).__name__}: {e}")


def classify(handler_type, status, body):
    """Map (status, body) to one of:
      PASS         — handler dispatched and returned a successful response
      SAFE_REJECT  — handler validated its inputs and returned a structured
                     refusal (missing arg, needs_confirm, no compositor, etc).
                     Counts as wired-and-correct.
      TIMEOUT      — handler hung past 8s
      ERROR        — uncaught exception
    """
    if status == "TIMEOUT":
        return "TIMEOUT", "8s timeout"
    if status == "EXCEPT":
        return "ERROR", body
    # status == "OK"
    if not isinstance(body, dict):
        return "PASS", f"non-dict response: {type(body).__name__}"
    # Structured refusal patterns
    if body.get("success") is False:
        return "SAFE_REJECT", body.get("error", body.get("message", "success=false"))[:80]
    if body.get("needs_confirm") or body.get("confirmation_required"):
        return "SAFE_REJECT", "needs_confirm"
    if body.get("needs_clarification"):
        return "SAFE_REJECT", "needs_clarification"
    if body.get("error"):
        return "SAFE_REJECT", str(body["error"])[:80]
    return "PASS", str({k: body[k] for k in list(body)[:3]})[:120]


async def main():
    try:
        from contusion_handlers import HANDLERS
    except Exception as e:
        print(json.dumps({"fatal": f"import_failed: {e}"}))
        sys.exit(1)

    out = {
        "total_handlers": len(HANDLERS),
        "skipped_destructive": [],
        "results": {},
        "tally": {"PASS": 0, "SAFE_REJECT": 0, "TIMEOUT": 0, "ERROR": 0, "SKIP": 0},
        "by_family": {},
        "errors_detail": [],
        "timeouts_detail": [],
    }

    for k in sorted(HANDLERS.keys()):
        if k in DESTRUCTIVE:
            out["skipped_destructive"].append(k)
            out["tally"]["SKIP"] += 1
            out["results"][k] = {"category": "SKIP", "detail": "destructive"}
            continue

        fn = HANDLERS[k]
        t0 = time.time()
        status, body = await call(fn, {})
        elapsed_ms = int((time.time() - t0) * 1000)

        category, detail = classify(k, status, body)
        out["tally"][category] += 1
        out["results"][k] = {"category": category, "detail": detail, "elapsed_ms": elapsed_ms}

        family = k.split(".")[0] if "." in k else "_root"
        if family not in out["by_family"]:
            out["by_family"][family] = {"PASS": 0, "SAFE_REJECT": 0, "TIMEOUT": 0, "ERROR": 0, "SKIP": 0}
        out["by_family"][family][category] += 1

        if category == "ERROR":
            out["errors_detail"].append({"handler": k, "detail": detail})
        elif category == "TIMEOUT":
            out["timeouts_detail"].append(k)

    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
