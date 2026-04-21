#!/usr/bin/env python3
"""Probe v2 dictionary for routable phrases."""
import os
import sys

os.environ["AICONTROL_DICTIONARY_V2_PATH"] = "/tmp/dv2.pkl.zst"
sys.path.insert(0, "/mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control/ai-control/daemon")

from dictionary_v2 import lookup  # noqa: E402

candidates = [
    # AUDIO
    "raise the volume", "lower volume", "turn the volume up", "turn the volume down",
    "make it louder", "make it quieter", "vol up", "vol down",
    "mute", "unmute", "toggle mute", "silence", "mute the sound",
    "mute the mic", "unmute the mic", "toggle the microphone",
    "show audio outputs", "list audio sinks",
    # BRIGHTNESS
    "raise the brightness", "lower the brightness", "make it brighter",
    "make it darker", "dim the screen", "brighten the screen",
    "max brightness", "minimum brightness", "auto brightness",
    "what is the brightness", "current brightness", "brightness level",
    # MEDIA
    "play", "pause", "play music", "pause music", "play the music",
    "next track", "skip", "skip ahead", "next song please",
    "previous track", "back to the last song",
    "stop the music", "kill the music",
    "now playing", "what's playing", "media status",
    "list media players", "show media players",
    "play pause", "play/pause", "toggle playback",
    # POWER
    "lock the screen", "lock screen", "lockscreen", "lock my session",
    "unlock the screen", "wake up",
    "turn off the screen", "shut off the screen", "screen sleep",
    "turn on the screen", "wake the screen",
    # SYSTEM
    "screenshot", "take a screenshot", "screenshot please",
    "screenshot the window", "screenshot active window",
    "screenshot a region", "snipping tool",
    "send a notification", "notify me",
    "toggle night light", "turn on night light", "warmer screen",
    "open clipboard monitor", "show clipboard monitor",
    # MONITORING
    "battery", "battery level", "battery percent", "battery status", "battery left",
    "battery time remaining", "battery time left", "battery estimate",
    "cpu freq", "cpu frequency", "cpu speed", "current cpu clock",
    "gpu status", "gpu info", "show gpu",
    "gpu temp", "gpu temperature", "how hot is the gpu",
    "fan speed", "fan rpm",
    "wifi signal", "wifi strength", "wifi quality",
    "show bluetooth", "list bluetooth", "show bluetooth devices",
    "show displays", "list displays", "list connected displays",
    "primary display", "main display",
    # WINDOW
    "list windows", "list open windows", "show windows", "what windows are open",
    "minimize this", "minimize the window", "min the window",
    "maximize this", "maximize the window",
    "restore the window", "unmaximize the window",
    "close this", "close the window", "close window", "x out",
    "fullscreen", "go fullscreen", "exit fullscreen", "f11", "toggle fullscreen",
    # WORKSPACE
    "list workspaces", "show workspaces", "show desktop",
    "next workspace", "next desktop", "ws next",
    "prev workspace", "previous workspace", "ws prev",
    "new workspace", "create workspace", "make a new desktop",
    "show all workspaces", "expose desktops", "overview", "mission control",
    # SERVICE
    "list services", "show services", "show systemd services", "list running services",
    # DRIVER
    "list drivers", "show drivers", "show loaded drivers", "show kernel modules",
    "lsmod", "what drivers are loaded",
    # SCRIPT
    "list scripts", "show scripts", "what scripts are available", "what scripts can i run",
    # APP / CLAUDE
    "is claude installed", "claude status", "do i have claude",
    "init claude workspace", "set up claude workspace", "claude workspace init",
    # GAME
    "list games", "show games", "what games are installed", "my game library",
    "what games are running", "running games", "is a game running",
    # CLIPBOARD
    "show clipboard", "what is on my clipboard", "what's in my clipboard",
    "clipboard contents", "paste preview",
    "clear clipboard", "empty clipboard", "wipe clipboard", "reset clipboard",
    "clipboard history", "show clipboard history", "list clipboard history",
    "paste at cursor", "paste here", "paste it",
]

hits = []
misses = []
for c in candidates:
    r = lookup(c)
    if r:
        hits.append((c, r["handler_type"], r["confidence"]))
    else:
        misses.append(c)

print(f"--- HITS ({len(hits)}/{len(candidates)}) ---")
# Group by family
by_family = {}
for phrase, handler, conf in hits:
    fam = handler.split(".", 1)[0]
    by_family.setdefault(fam, []).append((phrase, handler, conf))
for fam in sorted(by_family):
    print(f"\n[{fam}]")
    for phrase, handler, conf in sorted(by_family[fam]):
        print(f"  {phrase!r:50s} -> {handler:35s} conf={conf:.2f}")

print(f"\n--- MISSES ({len(misses)}/{len(candidates)}) ---")
for m in misses:
    print(f"  {m}")
