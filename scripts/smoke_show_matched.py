#!/usr/bin/env python3
import json, sys
d = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "/tmp/smoke_full.json"))
matched = [r for r in d["nl_commands"] if r["matched"]]
print(f"=== {len(matched)} MATCHED COMMANDS ===")
for r in matched:
    print(f"  {r['phrase']:35s} -> {r['actual_handler']:30s} success={r['success']} ({r['elapsed_ms']}ms)")
print()
miss = [r for r in d["nl_commands"] if not r["matched"]]
non_none = [r for r in miss if r["actual_handler"] is not None]
none_misses = [r for r in miss if r["actual_handler"] is None]
print(f"=== {len(non_none)} ROUTED-TO-WRONG-HANDLER ===")
for r in non_none:
    print(f"  '{r['phrase']}' wanted {r['expected_substr']} got {r['actual_handler']}")
print()
print(f"=== {len(none_misses)} NO-HANDLER (dictionary gap) ===")
for r in none_misses:
    print(f"  {r['phrase']}")
