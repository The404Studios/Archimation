#!/usr/bin/env python3
import json
import sys

d = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "/tmp/sweep_result.json"))

print("=== PASS details (handlers that fully ran) ===")
for k, v in sorted(d["results"].items()):
    if v["category"] == "PASS":
        ms = v["elapsed_ms"]
        det = v["detail"][:90]
        print(f"  {k:35s} ({ms:>4}ms) -> {det}")

print()
print("=== Sample SAFE_REJECT per family (first 2 each) ===")
fam_seen = {}
for k, v in sorted(d["results"].items()):
    if v["category"] != "SAFE_REJECT":
        continue
    fam = k.split(".")[0]
    fam_seen.setdefault(fam, [])
    if len(fam_seen[fam]) < 2:
        fam_seen[fam].append(k)
        det = v["detail"][:90]
        print(f"  {k:35s} -> {det}")
