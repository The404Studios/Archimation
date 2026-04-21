#!/usr/bin/env python3
"""catalysis_analysis.py -- S73-J: autocatalytic set analysis of the handler ecosystem.

Framework: Stuart Kauffman, *The Origins of Order* (1993) and *At Home in the
Universe* (1996). An autocatalytic set is a reaction network where every
product is produced by at least one reaction catalyzed by a member of the
set (catalytic closure). A handler registry is a software analog: every
handler that "runs" depends on catalytic infrastructure (helpers, imports,
binaries); the handlers that participate in closed loops are the
autocatalytic *core*; handlers with zero callers are the dead ends.

This script emits:
  * a directed dependency graph of the handler registry,
  * identification of load-bearing catalysts (high in-degree helpers),
  * identification of dead ends (zero-in-degree handlers),
  * an NK-landscape style complexity estimate across the handler bag,
  * a summary JSON suitable for /cortex dashboards.

Usage:
    python3 scripts/catalysis_analysis.py                 # pretty summary
    python3 scripts/catalysis_analysis.py --json          # machine-readable
    python3 scripts/catalysis_analysis.py --dot > g.dot   # graphviz
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DAEMON = REPO / "ai-control" / "daemon"

# Catalytic helpers we consider "infrastructure ribosomes". These are NOT
# themselves handlers, but every handler that performs work reaches one of
# these. Their removal would collapse the ecosystem -- true load-bearing
# catalysts in Kauffman's sense.
CATALYSTS: tuple[str, ...] = (
    "_exec", "_pctl", "_systemctl", "_tile", "_audio_vol",
    "_missing", "_bad_arg", "_envelope", "_with_error",
    "_no_session", "_compositor_status", "_q_exec",
    "_pe_resolve_path", "_pe_download", "_pe_parse_headers",
    "_pe_check_mz", "_pe_record_history",
)

# External binaries and Python modules the handlers depend on. These are the
# "environmental substrate" -- they have to exist for any reaction to fire.
EXTERNAL_BINS: tuple[str, ...] = (
    "playerctl", "systemctl", "wmctrl", "xdotool", "pactl",
    "brightnessctl", "curl", "peloader", "notify-send", "grim",
    "scrot", "bluetoothctl", "redshift", "gammastep", "pkill",
)


def _parse_handlers(src_path: Path) -> dict[str, Any]:
    """Parse contusion_handlers.py as an AST. Return handler function nodes
    and HANDLERS[...] registration statements."""
    source = src_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    handler_fns: dict[str, ast.AsyncFunctionDef] = {}
    handler_type_to_fn: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            handler_fns[node.name] = node
        # Match: HANDLERS["x.y"] = fn_name
        if (isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Subscript)
                and isinstance(node.targets[0].value, ast.Name)
                and node.targets[0].value.id == "HANDLERS"):
            key_node = node.targets[0].slice
            if isinstance(key_node, ast.Constant) and isinstance(node.value, ast.Name):
                handler_type_to_fn[key_node.value] = node.value.id

    # Also detect handlers registered via a shared mutation pattern we use in
    # this file: lines of the form `HANDLERS["x.y"] = fn_name` -- AST catches
    # these above. For the non-registered handlers (drivers, game, perf,
    # etc. registered elsewhere), fall back to regex over the source.
    rx = re.compile(r'^\s*HANDLERS\["([a-z_]+\.[a-z_]+)"\]\s*=\s*(\w+)',
                    re.MULTILINE)
    for m in rx.finditer(source):
        handler_type_to_fn.setdefault(m.group(1), m.group(2))

    return {
        "source": source,
        "handler_fns": handler_fns,
        "handler_type_to_fn": handler_type_to_fn,
    }


def _calls_within(fn: ast.AsyncFunctionDef, names: set[str]) -> set[str]:
    """Return the subset of `names` that are called (await or direct) inside fn."""
    hits: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Name) and n.func.id in names:
                hits.add(n.func.id)
            elif isinstance(n.func, ast.Attribute) and n.func.attr in names:
                hits.add(n.func.attr)
    return hits


def build_graph(data: dict[str, Any]) -> dict[str, Any]:
    """Return:
      nodes:   list of {id, kind in {handler, catalyst, external}}
      edges:   list of {src, dst} (directed: caller -> callee)
      degree:  in_degree map (keyed by node id)
    """
    handler_fns = data["handler_fns"]
    type_to_fn = data["handler_type_to_fn"]
    source = data["source"]

    nodes: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    seen: set[str] = set()

    # Register all handlers as nodes under their handler_type id.
    fn_to_type: dict[str, str] = {v: k for k, v in type_to_fn.items()}
    for t in type_to_fn:
        nodes.append({"id": t, "kind": "handler"})
        seen.add(t)
    for c in CATALYSTS:
        nodes.append({"id": c, "kind": "catalyst"})
        seen.add(c)
    for b in EXTERNAL_BINS:
        nodes.append({"id": b, "kind": "external"})
        seen.add(b)

    catalyst_set = set(CATALYSTS)
    handler_fn_set = set(handler_fns.keys())
    all_names = catalyst_set | handler_fn_set

    # Edges from handlers to catalysts and other handlers
    for fn_name, fn_node in handler_fns.items():
        src_id = fn_to_type.get(fn_name, fn_name)
        if src_id not in seen:
            nodes.append({"id": src_id, "kind": "handler_unlisted"})
            seen.add(src_id)
        hits = _calls_within(fn_node, all_names)
        for h in hits:
            dst_id = fn_to_type.get(h, h)
            if dst_id not in seen:
                nodes.append({"id": dst_id, "kind": "catalyst" if h in catalyst_set else "handler"})
                seen.add(dst_id)
            if src_id != dst_id:
                edges.append({"src": src_id, "dst": dst_id})

    # Edges from handlers to external binaries (matched by argv[0] string lit)
    # Simple lexical scan on each handler's source slice.
    lines = source.splitlines()
    for fn_name, fn_node in handler_fns.items():
        start, end = fn_node.lineno - 1, (fn_node.end_lineno or fn_node.lineno)
        body_src = "\n".join(lines[start:end])
        src_id = fn_to_type.get(fn_name, fn_name)
        for b in EXTERNAL_BINS:
            # Match argv-style literal or shutil.which("bin") form.
            if re.search(r'\b["\']' + re.escape(b) + r'["\']', body_src):
                edges.append({"src": src_id, "dst": b})

    # Compute degree
    in_degree: dict[str, int] = defaultdict(int)
    out_degree: dict[str, int] = defaultdict(int)
    for e in edges:
        in_degree[e["dst"]] += 1
        out_degree[e["src"]] += 1
    # Make sure every node has an entry
    for n in nodes:
        in_degree.setdefault(n["id"], 0)
        out_degree.setdefault(n["id"], 0)

    return {"nodes": nodes, "edges": edges,
            "in_degree": dict(in_degree), "out_degree": dict(out_degree),
            "fn_to_type": fn_to_type}


def find_cycles(graph: dict[str, Any]) -> list[list[str]]:
    """Return all simple cycles up to a reasonable size. Cross-handler
    invocations should be few; any cycle is an autocatalytic loop worth
    flagging."""
    adj: dict[str, list[str]] = defaultdict(list)
    for e in graph["edges"]:
        adj[e["src"]].append(e["dst"])
    cycles: list[list[str]] = []
    # Tarjan-style SCC detection is heavy; since handler cross-calls are rare,
    # do a simple DFS looking only for cycles within the handler layer.
    handler_ids = {n["id"] for n in graph["nodes"]
                   if n["kind"].startswith("handler")}

    def dfs(node: str, stack: list[str], visited: set[str]) -> None:
        for nxt in adj.get(node, []):
            if nxt not in handler_ids:
                continue
            if nxt in stack:
                i = stack.index(nxt)
                cycles.append(stack[i:] + [nxt])
                continue
            if nxt in visited:
                continue
            dfs(nxt, stack + [nxt], visited)
        visited.add(node)

    visited: set[str] = set()
    for h in handler_ids:
        if h not in visited:
            dfs(h, [h], visited)
    # Dedupe rotationally-equivalent cycles
    canon: set[tuple[str, ...]] = set()
    unique: list[list[str]] = []
    for c in cycles:
        if len(c) < 2:
            continue
        trim = c[:-1]  # drop closure repeat
        best = min(tuple(trim[i:] + trim[:i]) for i in range(len(trim)))
        if best not in canon:
            canon.add(best)
            unique.append(list(best) + [best[0]])
    return unique


def nk_metric(graph: dict[str, Any]) -> dict[str, Any]:
    """NK-landscape framing. N = number of handlers. K = average out-degree
    toward *other handlers* (i.e. how many handler decisions each handler's
    behaviour couples to, NOT counting infrastructure edges). K = 0 means a
    smooth, Class-1 landscape (every handler independent); K = N-1 is
    maximally rugged. Class-4 edge-of-chaos lives near K ~ 2-6."""
    handler_ids = [n["id"] for n in graph["nodes"]
                   if n["kind"].startswith("handler")]
    n = len(handler_ids)
    handler_edges = [e for e in graph["edges"]
                     if e["src"] in handler_ids and e["dst"] in handler_ids]
    k_avg = (len(handler_edges) / n) if n else 0.0
    if k_avg < 0.5:
        regime = "Class-1 smooth (largely independent handlers; refactoring safe)"
    elif k_avg < 2.0:
        regime = "Class-2 weakly coupled"
    elif k_avg < 6.0:
        regime = "Class-4 edge-of-chaos (tune carefully)"
    else:
        regime = "Class-3 rugged (high risk of cascading regressions)"
    return {"N": n, "K_avg": round(k_avg, 3),
            "regime": regime,
            "handler_to_handler_edges": len(handler_edges)}


def summarize(graph: dict[str, Any]) -> dict[str, Any]:
    in_deg = graph["in_degree"]
    out_deg = graph["out_degree"]
    nodes = graph["nodes"]

    # Top catalysts by in-degree (ribosomes of the handler network)
    catalysts = sorted(
        [(n["id"], in_deg[n["id"]]) for n in nodes if n["kind"] == "catalyst"],
        key=lambda kv: -kv[1])

    # Dead-end handlers: handlers that nothing else calls. In our ecosystem
    # that's *most* of them (NL routes in, but no handler re-dispatches).
    dead_ends = [n["id"] for n in nodes
                 if n["kind"].startswith("handler") and in_deg[n["id"]] == 0]

    # High-out handlers (coupling points)
    hot_callers = sorted(
        [(n["id"], out_deg[n["id"]]) for n in nodes
         if n["kind"].startswith("handler")],
        key=lambda kv: -kv[1])[:10]

    cycles = find_cycles(graph)
    nk = nk_metric(graph)

    return {
        "counts": {
            "handlers": sum(1 for n in nodes if n["kind"].startswith("handler")),
            "catalysts": sum(1 for n in nodes if n["kind"] == "catalyst"),
            "external_bins": sum(1 for n in nodes if n["kind"] == "external"),
            "edges": len(graph["edges"]),
        },
        "top_catalysts": catalysts[:12],
        "dead_end_count": len(dead_ends),
        "dead_end_sample": dead_ends[:15],
        "hot_callers": hot_callers,
        "cycles": cycles,
        "nk": nk,
    }


def emit_dot(graph: dict[str, Any]) -> str:
    out = ["digraph handlers {",
           '  rankdir=LR;',
           '  node [shape=box,style="rounded,filled"];']
    kind_color = {
        "handler": "#d9e8ff",
        "handler_unlisted": "#ffd9d9",
        "catalyst": "#fff3b0",
        "external": "#d9d9d9",
    }
    for n in graph["nodes"]:
        c = kind_color.get(n["kind"], "white")
        out.append(f'  "{n["id"]}" [fillcolor="{c}"];')
    for e in graph["edges"]:
        out.append(f'  "{e["src"]}" -> "{e["dst"]}";')
    out.append("}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("--dot", action="store_true", help="emit graphviz DOT")
    ap.add_argument("--source", default=str(DAEMON / "contusion_handlers.py"),
                    help="path to contusion_handlers.py")
    args = ap.parse_args()

    src_path = Path(args.source)
    if not src_path.exists():
        print(f"error: {src_path} does not exist", file=sys.stderr)
        return 2

    data = _parse_handlers(src_path)
    graph = build_graph(data)
    summary = summarize(graph)

    if args.dot:
        print(emit_dot(graph))
        return 0
    if args.json:
        print(json.dumps({"graph": graph, "summary": summary}, indent=2))
        return 0

    print("ARCHWINDOWS handler catalysis analysis")
    print("=" * 60)
    c = summary["counts"]
    print(f"handlers: {c['handlers']}  catalysts: {c['catalysts']}  "
          f"external bins: {c['external_bins']}  edges: {c['edges']}")
    nk = summary["nk"]
    print(f"NK landscape: N={nk['N']} K_avg={nk['K_avg']}  "
          f"handler<->handler edges={nk['handler_to_handler_edges']}")
    print(f"regime: {nk['regime']}")
    print()
    print("Top catalysts (ribosomes of the ecosystem):")
    for name, deg in summary["top_catalysts"]:
        print(f"  {deg:>4} <- {name}")
    print()
    print(f"Dead-end handlers (zero callers, {summary['dead_end_count']} total):")
    for name in summary["dead_end_sample"]:
        print(f"  - {name}")
    if summary["dead_end_count"] > len(summary["dead_end_sample"]):
        print(f"  ... and {summary['dead_end_count'] - len(summary['dead_end_sample'])} more")
    print()
    print("Top coupled handlers (high out-degree):")
    for name, deg in summary["hot_callers"]:
        if deg:
            print(f"  {deg:>4} -> {name}")
    print()
    print("Autocatalytic cycles in the handler layer:")
    if not summary["cycles"]:
        print("  (none)  --  handler layer is a DAG; catalytic closure lives")
        print("  entirely in the infrastructure layer (_exec, _systemctl, etc.)")
    else:
        for cyc in summary["cycles"]:
            print("  " + " -> ".join(cyc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
