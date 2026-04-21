"""
Discrepancy detector for the bisim harness (roadmap §1.2.6 Item 6).

Compares two event streams (``observed`` vs ``oracle``) and classifies
the *first* divergence into one of four categories:

  * ``op-mismatch``      — different opcode at the same index.
  * ``length-mismatch``  — one stream ended before the other.
  * ``byte-mismatch``    — both sides have byte-like results (``bytes``,
                            hex str, list-of-ints) and they differ.
  * ``result-mismatch``  — any other shape mismatch on ``result``.

Positive test: a fabricated mismatch must produce exactly one record.
Negative test: matched traces must produce zero records.

The detector is deliberately NOT bound to the kernel ABI — it treats
events as opaque structural records so future oracles (RISC-V Verilator,
Coq proof state dump, etc.) can be compared with the same tool.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, Sequence


@dataclass
class Discrepancy:
    index: int
    category: str  # "op-mismatch" | "length-mismatch" | "byte-mismatch" | "result-mismatch"
    expected: Any
    actual: Any
    detail: str = ""

    def to_record(self) -> dict:
        return {
            "index": self.index,
            "category": self.category,
            "expected": self.expected,
            "actual": self.actual,
            "detail": self.detail,
        }


def _is_bytelike(x: Any) -> bool:
    if isinstance(x, (bytes, bytearray)):
        return True
    if isinstance(x, str):
        # treat hex strings (all lower hex digits, even length) as byte-like
        return len(x) > 0 and len(x) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in x)
    if isinstance(x, (list, tuple)) and x and all(isinstance(v, int) and 0 <= v < 256 for v in x):
        return True
    return False


def _normalize_bytes(x: Any) -> bytes:
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        return bytes.fromhex(x)
    if isinstance(x, (list, tuple)):
        return bytes(x)
    raise TypeError(f"cannot normalize to bytes: {type(x)}")


class DiscrepancyDetector:
    """Pluggable first-divergence finder.

    Methods return ``list[dict]`` rather than ``list[Discrepancy]`` so
    that downstream callers (pytest, CLI, JSON printers) don't need to
    import this module to consume results.
    """

    def diff(self, observed: Sequence[Any], oracle: Sequence[Any]) -> List[dict]:
        """Return a list of discrepancy records (first divergence only).

        Each element of ``observed``/``oracle`` may be either a
        ``trace_harness.TraceEvent`` (duck-typed via ``op``/``result``
        attributes) OR a plain dict with those keys. The detector never
        imports ``trace_harness`` to avoid a circular dep.
        """
        if len(observed) != len(oracle):
            return [Discrepancy(
                index=min(len(observed), len(oracle)),
                category="length-mismatch",
                expected=len(oracle),
                actual=len(observed),
                detail=f"observed has {len(observed)} events, oracle has {len(oracle)}",
            ).to_record()]

        for i, (obs, orc) in enumerate(zip(observed, oracle)):
            obs_op = getattr(obs, "op", None) if not isinstance(obs, dict) else obs.get("op")
            orc_op = getattr(orc, "op", None) if not isinstance(orc, dict) else orc.get("op")
            if obs_op != orc_op:
                return [Discrepancy(
                    index=i,
                    category="op-mismatch",
                    expected=orc_op,
                    actual=obs_op,
                ).to_record()]
            obs_r = getattr(obs, "result", None) if not isinstance(obs, dict) else obs.get("result")
            orc_r = getattr(orc, "result", None) if not isinstance(orc, dict) else orc.get("result")
            if obs_r == orc_r:
                continue
            # Different results — classify.
            if _is_bytelike(obs_r) and _is_bytelike(orc_r):
                try:
                    ob = _normalize_bytes(obs_r)
                    oc = _normalize_bytes(orc_r)
                except (ValueError, TypeError):
                    category, detail = "result-mismatch", "unparseable byte-like"
                else:
                    if len(ob) != len(oc):
                        category = "length-mismatch"
                        detail = f"bytes length differ: obs={len(ob)} orc={len(oc)}"
                    else:
                        category = "byte-mismatch"
                        diff_idx = next((k for k, (a, b) in enumerate(zip(ob, oc)) if a != b), -1)
                        detail = f"first differing byte at offset {diff_idx}"
            else:
                category = "result-mismatch"
                detail = f"types observed={type(obs_r).__name__} oracle={type(orc_r).__name__}"
            return [Discrepancy(
                index=i, category=category,
                expected=orc_r, actual=obs_r, detail=detail,
            ).to_record()]
        return []


__all__ = ["Discrepancy", "DiscrepancyDetector"]
