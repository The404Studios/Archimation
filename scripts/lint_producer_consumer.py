#!/usr/bin/env python3
"""lint_producer_consumer.py -- S74 Agent R: enforce invariant I-6.

I-6 (per docs/architecture-invariants.md §6): Every producer must have a
consumer. Any event-type / reason-code / verdict / enum-variant that names
a producible signal MUST have at least one emit site AND at least one
consumer (subscriber / switch-case / reader) in-tree.

A producer-without-consumer channel is either:
  * dead data (kernel cycles emitting signals no one reads),
  * a future attack surface (signals an attacker may learn to manipulate),
  * a silent regression (consumer used to exist and was deleted).

This lint grepps for producer DEFINEs / enum variants across the repo and
cross-checks them against emit sites and consumer sites (C callers,
Python bus.on(...) subscriptions, switch/case decodes). It baselines the
current violation set so existing known issues don't break CI; only NEW
violations trip --ci mode.

Exemption sentinel: append ``// lint: producer-consumer-exempt`` on the
same line as a producer #define / enum variant to skip it (for
hand-annotated dynamic-dispatch patterns where the consumer cannot be
statically located).

Usage:
    python3 scripts/lint_producer_consumer.py                         # report
    python3 scripts/lint_producer_consumer.py --json                  # JSON
    python3 scripts/lint_producer_consumer.py --write-baseline FILE   # seed
    python3 scripts/lint_producer_consumer.py --ci --baseline FILE    # gate
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

# ---------------------------------------------------------------------------
# Producer-source configuration
# ---------------------------------------------------------------------------
#
# Each producer source is a tuple of:
#   name         -- human-readable category
#   header_glob  -- Paths (relative to REPO) to scan for producer defs
#   producer_rx  -- regex matching a producer identifier on a declaration line
#   emit_patterns -- list of "what an emit site looks like" regex fragments;
#                    each must contain the placeholder {NAME} which gets
#                    substituted with the matched producer identifier.
#   emit_globs   -- file globs (relative to REPO) to search for emit sites
#   consumer_patterns, consumer_globs -- same shape for consumers
#
# For Python event_bus.py subscriptions the consumer pattern matches
# ``bus.on(..., <SymbolCls>.<NAME>, ...)`` where <SymbolCls> is the
# class name that wraps the producer space.


@dataclass
class ProducerSource:
    name: str
    header_globs: tuple[str, ...]
    producer_rx: str
    # Exclusion patterns: identifiers matching these are metadata, not
    # real producers (e.g. *_MAX sentinels, *_SIZE constants).
    exclude_suffixes: tuple[str, ...] = ()
    emit_patterns: tuple[str, ...] = ()
    emit_globs: tuple[str, ...] = ()
    consumer_patterns: tuple[str, ...] = ()
    consumer_globs: tuple[str, ...] = ()
    # Python enum-name that wraps this producer space, if any. Used for
    # recognising ``bus.on(SourceLayer.X, EnumName.NAME, handler)`` as a
    # consumer registration.
    python_enum_name: str | None = None
    python_short_name_map: dict[str, str] = field(default_factory=dict)


PRODUCER_SOURCES: tuple[ProducerSource, ...] = (
    ProducerSource(
        name="pe_event_bus",
        header_globs=("pe-loader/include/eventbus/*.h",
                      "services/scm/scm_event.h"),
        producer_rx=r"^#define\s+(PE_EVT_[A-Z0-9_]+|OBJ_EVT_[A-Z0-9_]+|"
                    r"TRUST_EVT_[A-Z0-9_]+|CORTEX_EVT_[A-Z0-9_]+|"
                    r"SVC_EVT_[A-Z0-9_]+)\s+0x[0-9A-Fa-f]+",
        exclude_suffixes=("_MAGIC", "_VERSION", "_MAX", "_SIZE",
                          "_MAX_SIZE", "_PACKED_SIZE", "_FLAG_URGENT",
                          "_FLAG_AUDIT", "_FLAG_REPLY_REQUESTED",
                          "_SRC_KERNEL", "_SRC_BROKER", "_SRC_RUNTIME",
                          "_SRC_SCM", "_SRC_CORTEX"),
        emit_patterns=(r"pe_event_emit\s*\(\s*{NAME}\b",
                       r"pe_event_emit_flags\s*\(\s*{NAME}\b",
                       r"scm_event_emit\s*\(\s*{NAME}\b"),
        emit_globs=("pe-loader/**/*.c", "pe-loader/**/*.h",
                    "services/**/*.c", "services/**/*.h"),
        consumer_patterns=(r"\b{ENUM}\.{SHORT}\b",
                           r"\bcase\s+{NAME}\s*:",
                           r"\btype\s*==\s*{NAME}\b",
                           r"\bevent_type\s*==\s*{NAME}\b"),
        consumer_globs=("ai-control/**/*.py", "pe-loader/**/*.c",
                        "pe-loader/**/*.h", "services/**/*.c"),
    ),
    ProducerSource(
        name="trust_algedonic_reason",
        header_globs=("trust/include/trust_algedonic.h",),
        producer_rx=r"^\s*(TRUST_ALG_[A-Z0-9_]+)\s*=",
        exclude_suffixes=("_MAX", "_RING_SLOTS", "_RING_MASK",
                          "_SEVERITY_INFO", "_SEVERITY_WARN",
                          "_SEVERITY_CRITICAL", "_SEVERITY_MAX"),
        emit_patterns=(r"trust_algedonic_emit\s*\([^)]*{NAME}\b",),
        emit_globs=("trust/**/*.c", "trust/**/*.h"),
        # Userspace consumer: algedonic_reader.py maps reason code to
        # short-name string. Any reason with a mapping entry counts as
        # subscribed.
        consumer_patterns=(r"{SHORT_LOWER}\b",
                           r"\bcase\s+{NAME}\s*:",),
        consumer_globs=("ai-control/**/*.py", "trust/**/*.c"),
    ),
    ProducerSource(
        name="trust_morphogen_event",
        header_globs=("trust/kernel/trust_morphogen.h",),
        producer_rx=r"^#define\s+(TRUST_MORPHOGEN_EVENT_[A-Z0-9_]+)\s+\d+U",
        exclude_suffixes=("_MAX",),
        emit_patterns=(r"trust_morphogen_perturb\s*\([^)]*{NAME}\b",
                       r"\?\s*{NAME}\b",
                       r":\s*{NAME}\b"),
        emit_globs=("trust/**/*.c",),
        consumer_patterns=(r"\bcase\s+{NAME}\s*:",),
        consumer_globs=("trust/**/*.c",),
    ),
    ProducerSource(
        name="trust_quorum_verdict",
        header_globs=("trust/include/trust_quorum.h",),
        producer_rx=r"^\s*(TRUST_QUORUM_[A-Z0-9_]+)\s*=",
        exclude_suffixes=(),
        emit_patterns=(r"return\s+{NAME}\b",
                       r"=\s*{NAME}\b",
                       r"{NAME}\s*;"),
        emit_globs=("trust/**/*.c",),
        consumer_patterns=(r"\bcase\s+{NAME}\s*:",
                           r"==\s*{NAME}\b",
                           r"!=\s*{NAME}\b"),
        consumer_globs=("trust/**/*.c", "ai-control/**/*.py"),
    ),
)


# ---------------------------------------------------------------------------
# File/IO helpers
# ---------------------------------------------------------------------------

EXEMPT_SENTINEL = "lint: producer-consumer-exempt"


def _load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _resolve_globs(globs: tuple[str, ...]) -> list[Path]:
    paths: list[Path] = []
    for g in globs:
        # Path.glob uses forward slashes; REPO is absolute Path
        paths.extend(REPO.glob(g))
    return [p for p in paths if p.is_file()]


def _short_of(full: str) -> str:
    """PE_EVT_LOAD -> LOAD; TRUST_ALG_POOL_EXHAUSTION -> POOL_EXHAUSTION."""
    # Strip off everything through the first 2+ leading tokens separated by _
    parts = full.split("_")
    # Drop the leading namespace prefix; heuristic: the prefix is everything
    # up to and including the one before the last word of the prefix family.
    prefix_len_map = {
        "PE_EVT_": 2, "OBJ_EVT_": 2, "TRUST_EVT_": 2,
        "CORTEX_EVT_": 2, "SVC_EVT_": 2,
        "TRUST_ALG_": 2, "TRUST_MORPHOGEN_EVENT_": 3,
        "TRUST_QUORUM_": 2,
    }
    for pre, n in prefix_len_map.items():
        if full.startswith(pre):
            return "_".join(parts[n:])
    return full


# ---------------------------------------------------------------------------
# Producer discovery
# ---------------------------------------------------------------------------

def _discover_producers(src: ProducerSource) -> list[dict[str, Any]]:
    """Scan src.header_globs for producer identifiers. Return list of
    {name, short, source, file, line, exempt}."""
    found: list[dict[str, Any]] = []
    rx = re.compile(src.producer_rx)
    for hg in src.header_globs:
        for path in _resolve_globs((hg,)):
            text = _load_text(path)
            for lineno, line in enumerate(text.splitlines(), start=1):
                m = rx.search(line)
                if not m:
                    continue
                name = m.group(1)
                if any(name.endswith(sfx) for sfx in src.exclude_suffixes):
                    continue
                exempt = EXEMPT_SENTINEL in line
                found.append({
                    "name": name,
                    "short": _short_of(name),
                    "source": src.name,
                    "file": str(path.relative_to(REPO)).replace("\\", "/"),
                    "line": lineno,
                    "exempt": exempt,
                })
    return found


# ---------------------------------------------------------------------------
# Emit / consumer checks
# ---------------------------------------------------------------------------

def _grep_count(patterns: tuple[str, ...], globs: tuple[str, ...],
                name: str, short: str, exclude_file: Path | None) -> int:
    """Count matches of any ``patterns`` (with placeholders resolved)
    across files matching ``globs``. Skip the declaration file so the
    grep doesn't count the #define itself."""
    subs: dict[str, str] = {
        "NAME": re.escape(name),
        "SHORT": re.escape(short),
        "SHORT_LOWER": re.escape(short.lower()),
    }

    # Compile patterns; for event bus consumer pattern that uses {ENUM} we
    # need to check each Python enum name. The pattern is expanded per
    # enum in the caller.
    total = 0
    files = _resolve_globs(globs)
    if exclude_file:
        files = [p for p in files if p.resolve() != exclude_file.resolve()]
    compiled: list[re.Pattern[str]] = []
    for raw_pat in patterns:
        try:
            body = raw_pat
            for key, val in subs.items():
                body = body.replace("{" + key + "}", val)
            compiled.append(re.compile(body))
        except re.error:
            # Malformed pattern after substitution -- skip but don't crash.
            continue

    for path in files:
        text = _load_text(path)
        if not text:
            continue
        for pat in compiled:
            total += len(pat.findall(text))
            if total > 0 and name == short:
                # Early exit tiny optimisation only when we're sure
                # counts aren't interesting.
                break
    return total


# PE-event-bus consumer: Python bus.on(SourceLayer.X, <Enum>.<SHORT>, ...).
# The producer prefix maps to a Python enum name.
_PY_ENUM_FOR_PREFIX = {
    "PE_EVT_": "PeEventType",
    "OBJ_EVT_": "BrokerEventType",
    "TRUST_EVT_": "TrustEventType",
    "CORTEX_EVT_": "CortexEventType",
    "SVC_EVT_": "SvcEventType",
}


def _python_subscriber_count(name: str, short: str) -> int:
    """Count Python bus.on(..., <Enum>.<SHORT>, ...) sites matching the
    given producer. Returns 0 if the producer prefix has no Python enum."""
    enum = None
    for pre, en in _PY_ENUM_FOR_PREFIX.items():
        if name.startswith(pre):
            enum = en
            break
    if enum is None:
        return 0
    rx = re.compile(rf"\b{re.escape(enum)}\.{re.escape(short)}\b")
    n = 0
    for path in _resolve_globs(("ai-control/**/*.py",)):
        text = _load_text(path)
        n += len(rx.findall(text))
    return n


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyse() -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for src in PRODUCER_SOURCES:
        producers = _discover_producers(src)
        header_path = (REPO / src.header_globs[0]).resolve() \
            if src.header_globs else None
        for p in producers:
            if p["exempt"]:
                p["status"] = "exempt"
                p["emit_count"] = 0
                p["consumer_count"] = 0
                p["severity"] = "ok"
                results.append(p)
                by_source[src.name].append(p)
                continue

            emit_n = _grep_count(src.emit_patterns, src.emit_globs,
                                 p["name"], p["short"], header_path)
            c_hits = _grep_count(src.consumer_patterns, src.consumer_globs,
                                 p["name"], p["short"], header_path)
            py_subs = _python_subscriber_count(p["name"], p["short"])
            consumer_n = c_hits + py_subs

            p["emit_count"] = emit_n
            p["consumer_count"] = consumer_n
            p["python_subscribers"] = py_subs

            if emit_n == 0 and consumer_n == 0:
                p["status"] = "orphaned"
                p["severity"] = "high"
            elif emit_n == 0:
                p["status"] = "no_emit"
                p["severity"] = "medium"
            elif consumer_n == 0:
                p["status"] = "no_consumer"
                p["severity"] = "high"
            else:
                p["status"] = "ok"
                p["severity"] = "ok"
            results.append(p)
            by_source[src.name].append(p)

    counts = {
        "ok": sum(1 for r in results if r["status"] == "ok"),
        "exempt": sum(1 for r in results if r["status"] == "exempt"),
        "no_emit": sum(1 for r in results if r["status"] == "no_emit"),
        "no_consumer": sum(1 for r in results if r["status"] == "no_consumer"),
        "orphaned": sum(1 for r in results if r["status"] == "orphaned"),
        "total": len(results),
    }
    return {"results": results, "by_source": dict(by_source), "counts": counts}


# ---------------------------------------------------------------------------
# Reporting / baselining / CI gate
# ---------------------------------------------------------------------------

def _format_report(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    c = summary["counts"]
    lines.append("ARCHWINDOWS producer-consumer lint (I-6)")
    lines.append("=" * 60)
    lines.append(f"producers scanned: {c['total']}  "
                 f"ok={c['ok']}  exempt={c['exempt']}  "
                 f"no_emit={c['no_emit']}  "
                 f"no_consumer={c['no_consumer']}  "
                 f"orphaned={c['orphaned']}")
    lines.append("")
    for src_name, prods in summary["by_source"].items():
        lines.append(f"[{src_name}]  ({len(prods)} producers)")
        for p in prods:
            if p["status"] == "ok":
                continue
            tag = {
                "no_emit": "NO-EMIT",
                "no_consumer": "NO-CONSUMER",
                "orphaned": "ORPHANED",
                "exempt": "EXEMPT",
            }.get(p["status"], p["status"].upper())
            lines.append(f"  [{tag}] {p['name']}  "
                         f"(emits={p.get('emit_count', 0)}, "
                         f"consumers={p.get('consumer_count', 0)})  "
                         f"@ {p['file']}:{p['line']}")
        lines.append("")
    return "\n".join(lines)


def _baseline_payload(summary: dict[str, Any]) -> dict[str, Any]:
    """Reduce summary to the frozen baseline shape.

    We record each non-OK producer by name; CI fails only if a producer NOT
    in the baseline shows up as non-OK, OR a baselined producer transitions
    to a WORSE severity."""
    by_name: dict[str, dict[str, Any]] = {}
    for r in summary["results"]:
        if r["status"] == "ok":
            continue
        by_name[r["name"]] = {
            "status": r["status"],
            "file": r["file"],
            "line": r["line"],
            "source": r["source"],
        }
    return {
        "schema_version": 1,
        "counts": summary["counts"],
        "known_violations": by_name,
    }


_SEVERITY_RANK = {"ok": 0, "exempt": 0, "no_emit": 1, "no_consumer": 2,
                  "orphaned": 2}


def _run_ci_gate(summary: dict[str, Any], baseline_path: Path,
                 out_path: Path | None) -> int:
    try:
        base = json.loads(baseline_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"error: baseline not found: {baseline_path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"error: baseline parse: {e}", file=sys.stderr)
        return 2

    known = base.get("known_violations", {})
    new_violations: list[dict[str, Any]] = []
    regressions: list[dict[str, Any]] = []
    current: dict[str, dict[str, Any]] = {}
    for r in summary["results"]:
        # "ok" and "exempt" never count against CI -- exempt is the explicit
        # escape hatch for dynamic-dispatch patterns that cannot be
        # statically linked to a consumer.
        if r["status"] in ("ok", "exempt"):
            continue
        current[r["name"]] = r
        if r["name"] not in known:
            new_violations.append(r)
            continue
        # Baselined: check severity didn't worsen.
        base_rank = _SEVERITY_RANK.get(known[r["name"]]["status"], 2)
        cur_rank = _SEVERITY_RANK.get(r["status"], 2)
        if cur_rank > base_rank:
            regressions.append({"name": r["name"],
                                "baseline": known[r["name"]]["status"],
                                "current": r["status"]})

    report: dict[str, Any] = {
        "new_violations": new_violations,
        "regressions": regressions,
        "current_counts": summary["counts"],
        "baseline_counts": base.get("counts", {}),
        "status": "fail" if (new_violations or regressions) else "pass",
    }
    if out_path is not None:
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if new_violations or regressions:
        print("producer-consumer lint: FAIL", file=sys.stderr)
        for v in new_violations:
            print(f"  new violation: {v['name']} ({v['status']}) "
                  f"@ {v['file']}:{v['line']}", file=sys.stderr)
        for r in regressions:
            print(f"  regression: {r['name']} "
                  f"{r['baseline']} -> {r['current']}", file=sys.stderr)
        return 1
    print(f"producer-consumer lint: PASS "
          f"(known={len(known)}, current_nonok={len(current)})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON")
    ap.add_argument("--ci", action="store_true",
                    help="CI gate mode: compare against baseline; "
                    "nonzero exit on NEW violations or regressions")
    ap.add_argument("--baseline",
                    default=str(HERE / "producer_consumer_baseline.json"))
    ap.add_argument("--out", default=None,
                    help="write JSON report to this path (--ci mode)")
    ap.add_argument("--write-baseline", default=None,
                    help="record current state as baseline JSON at this path")
    args = ap.parse_args()

    summary = analyse()

    if args.write_baseline:
        payload = _baseline_payload(summary)
        Path(args.write_baseline).write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"wrote baseline: {args.write_baseline}")
        print(f"  known violations: {len(payload['known_violations'])}")
        return 0

    if args.ci:
        out_path = Path(args.out) if args.out else None
        return _run_ci_gate(summary, Path(args.baseline), out_path)

    if args.json:
        print(json.dumps(summary, indent=2, default=str))
        return 0

    print(_format_report(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
