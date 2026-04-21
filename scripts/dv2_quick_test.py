#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ai-control", "daemon"))
from dictionary_v2 import lookup

phrases = [
    "crank up the volume", "make it quieter", "kill the music",
    "how bright is my screen", "battery please", "show bluetooth",
    "hey can you screenshot", "toggle the night light", "is claude installed",
    "shut off the display", "list my windows", "what music is on",
    "lower the brightness please", "could you mute that", "next track",
    "previous song", "skip this", "list workspaces",
    "show running services", "list drivers", "list scripts",
]
ok = 0
for p in phrases:
    r = lookup(p)
    if r:
        h = r["handler_type"]
        c = r["confidence"]
        print(f"  [OK ] {p:38s} -> {h:30s} conf={c:.2f}")
        ok += 1
    else:
        print(f"  [MISS] {p}")
print(f"--- {ok}/{len(phrases)} routed ---")
