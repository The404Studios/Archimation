"""
Trace harness for the Root-of-Authority empirical bisimulation (roadmap
§1.2.6 Item 6). This is the orchestrator that drives a sequence of
actions against two oracles — the kernel-under-test and a reference
oracle — and records the observed (actor, op, args, result) tuples as a
JSON-addressable event stream.

Design pillars (from roadmap §1.2.6 Item 6 and behavioral memory
``feedback_user_favors_coherence_over_velocity.md``):

  * The *harness* is stdlib-only Python. It runs on any WSL-dev host
    without needing libtrust, RISC-V toolchains, or Verilator.
  * The *oracles* are pluggable ABCs. Concrete oracles plug in at run
    time:
      - ``KernelOracle``  — wraps libtrust via ctypes; requires
        ``/dev/trust`` (only available on ARCHIMATION-booted kernels).
      - ``MockOracle``    — pure Python; records expected behavior
        declaratively. Used as the negative control in harness unit
        tests (matched traces → zero discrepancies).
      - Future ``RiscvVerilatorOracle`` — blocked on Agent F's kprobe
        syscall-tracer port (roadmap Item 8).
  * Trace events are JSON-serializable ``dict``s so that the harness
    can be replayed offline by another language (a future Rust/Go
    discrepancy detector or a jq one-liner filter).

Event schema::

    {
      "ts":     float,    # wall-clock at record time
      "seq":    int,      # monotonic within a single trace
      "actor":  str,      # "kernel" | "oracle" | "mock" | ...
      "op":     str,      # action opcode: "proof_mint", "proof_consume", ...
      "args":   list,     # JSON-native arguments
      "result": any       # JSON-serializable result (dict, list, primitive)
    }

Typical flow::

    harness = BisimHarness()
    oracle  = MockOracle(script=[(0, "proof_mint", [42], {"proof": "ab12..."})])
    observed = harness.record_trace(["proof_mint"], oracle)
    expected = harness.record_trace(["proof_mint"], oracle)  # matching
    report   = harness.diff_traces(observed, expected)
    assert not report.has_divergence
"""
from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------- #
# Trace event schema                                                    #
# --------------------------------------------------------------------- #
@dataclass
class TraceEvent:
    """One atom of the recorded bisim trace."""
    ts: float
    seq: int
    actor: str
    op: str
    args: List[Any] = field(default_factory=list)
    result: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "TraceEvent":
        return TraceEvent(
            ts=float(d.get("ts", 0.0)),
            seq=int(d.get("seq", 0)),
            actor=str(d.get("actor", "")),
            op=str(d.get("op", "")),
            args=list(d.get("args", []) or []),
            result=d.get("result"),
        )


@dataclass
class Trace:
    """Ordered list of TraceEvents with JSON in/out helpers."""
    events: List[TraceEvent] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def append(self, ev: TraceEvent) -> None:
        self.events.append(ev)

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self):
        return iter(self.events)

    def to_json(self) -> str:
        return json.dumps({
            "meta": self.meta,
            "events": [ev.to_dict() for ev in self.events],
        }, indent=2, sort_keys=True, default=str)

    @staticmethod
    def from_json(s: str) -> "Trace":
        raw = json.loads(s)
        t = Trace(meta=dict(raw.get("meta", {})))
        for d in raw.get("events", []):
            t.append(TraceEvent.from_dict(d))
        return t

    def save(self, path: Path) -> None:
        path.write_text(self.to_json(), encoding="utf-8")

    @staticmethod
    def load(path: Path) -> "Trace":
        return Trace.from_json(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------- #
# OracleAdapter ABC                                                      #
# --------------------------------------------------------------------- #
@dataclass
class Action:
    """A single request to an oracle."""
    op: str
    args: List[Any] = field(default_factory=list)


class OracleAdapter(ABC):
    """Abstract oracle for the bisim harness.

    Concrete oracles produce ``(op, args) -> result`` deterministically
    for the same state-hash prefix. Implementations should be stateful
    *but* expose their state via ``get_state_hash()`` so the harness can
    checkpoint.
    """

    actor_name: str = "abstract"

    @abstractmethod
    def submit_action(self, action: Action) -> Any:
        """Execute ``action``. Return a JSON-serializable result."""

    @abstractmethod
    def get_state_hash(self) -> bytes:
        """Return a short fingerprint of the oracle's current state."""

    def close(self) -> None:
        """Release any external resources (device handles, etc.)."""
        return None


class MockOracle(OracleAdapter):
    """Scripted oracle. Script entries are ``(op, [args...], result)``.

    A typical use-case: generate a trace we *expect* the kernel to
    match, and feed it through ``record_trace``/``diff_traces`` as the
    reference arm. If the kernel wiring drifts, the mock and kernel
    traces diverge and the detector flags it.
    """

    actor_name = "mock"

    def __init__(self, script: Optional[Iterable[Tuple[str, List[Any], Any]]] = None):
        self._script: List[Tuple[str, List[Any], Any]] = list(script or [])
        self._idx = 0
        self._state = bytearray(8)  # toy 64-bit state-hash material

    def extend(self, entries: Iterable[Tuple[str, List[Any], Any]]) -> None:
        self._script.extend(entries)

    def submit_action(self, action: Action) -> Any:
        if self._idx >= len(self._script):
            raise RuntimeError(
                f"MockOracle exhausted: got {action.op!r} but no script entry left")
        op, args, result = self._script[self._idx]
        if op != action.op or list(args) != list(action.args):
            raise RuntimeError(
                f"MockOracle script mismatch at #{self._idx}: "
                f"expected {op!r} args={args!r}, got {action.op!r} args={action.args!r}")
        self._idx += 1
        # Fold op + result into the state-hash (stable, deterministic).
        enc = (op + repr(result)).encode("utf-8")
        for i, b in enumerate(enc):
            self._state[i % 8] ^= b
        return result

    def get_state_hash(self) -> bytes:
        return bytes(self._state)


class KernelOracle(OracleAdapter):
    """Wraps the live kernel via libtrust ctypes.

    On a WSL dev host without ``/dev/trust`` this oracle's ``__init__``
    will raise and the harness will skip the kernel arm. The intended
    deployment path is:

       1. Boot the ARCHIMATION ISO in QEMU (roadmap §0.4 moat).
       2. Mount the source tree via 9p/virtio.
       3. Run pytest; ``KernelOracle.__init__`` finds ``libtrust.so.1``.

    Operations exposed (op-string mapping to libtrust calls):
      * ``"proof_mint"``    -> ``trust_proof_mint(subject_id)`` returns
                                 hex(proof).
      * ``"proof_consume"`` -> ``trust_proof_consume(subject_id, proof)``
                                 returns hex(next_proof).
      * ``"proof_verify"``  -> ``trust_proof_verify(subject_id)`` returns
                                 int errno (0 on success).
      * ``"get_nonce"``     -> ``trust_proof_get_nonce(subject_id)`` returns
                                 int.
    """

    actor_name = "kernel"

    def __init__(self, libtrust_path: Optional[str] = None):
        import ctypes
        import ctypes.util
        name = libtrust_path or ctypes.util.find_library("trust")
        if name is None:
            # Deliberate: this oracle is NOT usable on a non-ARCHIMATION host.
            # The smoke test skips cleanly when this raises.
            raise OSError("libtrust not found — KernelOracle unavailable")
        self._lib = ctypes.CDLL(name)
        # We deliberately avoid setting full argtypes here because the
        # harness treats the kernel oracle as a black box; the real
        # wiring belongs to tests/integration once Agent F's kprobe
        # port lands.
        init_fn = getattr(self._lib, "trust_init", None)
        if init_fn is not None:
            rc = init_fn()
            if rc != 0:
                raise OSError(f"trust_init() failed with {rc}")
        self._state = bytearray(8)

    def submit_action(self, action: Action) -> Any:
        # Full libtrust dispatch is out of scope for the S75 pure-cross
        # probe — this method exists so the harness shape is validated.
        # It raises so smoke tests that accidentally hit this path on a
        # WSL host fail loudly rather than silently passing.
        raise NotImplementedError(
            "KernelOracle.submit_action requires Agent F's kprobe port "
            "and a live /dev/trust; currently deferred to roadmap Item 8.")

    def get_state_hash(self) -> bytes:
        return bytes(self._state)


# --------------------------------------------------------------------- #
# BisimHarness                                                           #
# --------------------------------------------------------------------- #
@dataclass
class DiffReport:
    """Result of ``BisimHarness.diff_traces``."""
    has_divergence: bool
    first_divergence_index: Optional[int] = None
    summary: str = ""
    per_event_issues: List[Dict[str, Any]] = field(default_factory=list)


class BisimHarness:
    """Orchestrates action sequences against one or more oracles.

    Intentionally framework-light: no pytest, no dataclasses beyond the
    above, no threads. Reproducibility is paramount — the harness is the
    component that a peer reviewer will want to re-run on their own
    laptop before believing an FPGA-vs-kernel equivalence claim.
    """

    def __init__(self, clock: Optional[Callable[[], float]] = None):
        self._clock = clock or time.monotonic
        self._seq = 0

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    # ---------------- Recording ------------------------------------- #
    def record_trace(
        self,
        action_sequence: Iterable[Action | Tuple[str, List[Any]] | str],
        oracle: OracleAdapter,
    ) -> Trace:
        """Drive ``oracle`` through ``action_sequence`` and record."""
        trace = Trace(meta={
            "actor": oracle.actor_name,
            "recorded_at": self._clock(),
            "state_hash_begin": oracle.get_state_hash().hex(),
        })
        for item in action_sequence:
            if isinstance(item, Action):
                action = item
            elif isinstance(item, tuple):
                op, args = item
                action = Action(op=op, args=list(args))
            elif isinstance(item, str):
                action = Action(op=item, args=[])
            else:
                raise TypeError(f"unsupported action-sequence item: {item!r}")
            result = oracle.submit_action(action)
            ev = TraceEvent(
                ts=self._clock(),
                seq=self._next_seq(),
                actor=oracle.actor_name,
                op=action.op,
                args=list(action.args),
                result=result,
            )
            trace.append(ev)
        trace.meta["state_hash_end"] = oracle.get_state_hash().hex()
        return trace

    # ---------------- Replay ---------------------------------------- #
    def replay_trace(self, trace: Trace, oracle: OracleAdapter) -> Trace:
        """Re-issue ``trace``'s ops against ``oracle`` and return a new trace."""
        action_sequence = [Action(op=ev.op, args=list(ev.args)) for ev in trace]
        return self.record_trace(action_sequence, oracle)

    # ---------------- Diff ------------------------------------------ #
    def diff_traces(self, observed: Trace, oracle: Trace) -> DiffReport:
        """Compare two traces event-by-event and surface first divergence.

        This is the harness-level view; the per-field categorical
        taxonomy (byte-mismatch / length-mismatch / op-mismatch /
        result-mismatch) lives in ``discrepancy_detector.DiscrepancyDetector``
        to keep the harness small.
        """
        try:
            from .discrepancy_detector import DiscrepancyDetector
        except ImportError:
            # Pytest may import this module standalone (no package context)
            # when the ``tests`` tree has no ``__init__.py``. Fall back to
            # an absolute import with the bisim dir on sys.path (conftest
            # / test_bisim_smoke.py ensure that).
            from discrepancy_detector import DiscrepancyDetector
        detector = DiscrepancyDetector()
        records = detector.diff(observed.events, oracle.events)
        if not records:
            return DiffReport(
                has_divergence=False,
                summary=f"matched {len(observed)} events; no divergence",
            )
        first = records[0]
        return DiffReport(
            has_divergence=True,
            first_divergence_index=first["index"],
            summary=(
                f"first divergence at event #{first['index']}: "
                f"{first['category']} "
                f"(expected {first.get('expected')!r}, "
                f"actual {first.get('actual')!r})"
            ),
            per_event_issues=records,
        )


# --------------------------------------------------------------------- #
# End-to-end smoke helper (used by test_bisim_smoke)                     #
# --------------------------------------------------------------------- #
def run_e2e_smoke() -> Tuple[Trace, Trace, DiffReport]:
    """Round-trip: record from mock, replay on a fresh mock, diff."""
    script = [
        ("proof_mint", [1], {"proof": "ab" * 16}),
        ("proof_consume", [1, "ab" * 16], {"next_proof": "cd" * 16}),
        ("get_nonce", [1], {"nonce": 1}),
    ]
    oracle_a = MockOracle(script=script)
    oracle_b = MockOracle(script=script)
    h = BisimHarness()
    observed = h.record_trace(
        [Action(op=op, args=args) for (op, args, _) in script], oracle_a)
    expected = h.record_trace(
        [Action(op=op, args=args) for (op, args, _) in script], oracle_b)
    report = h.diff_traces(observed, expected)
    return observed, expected, report


__all__ = [
    "Action",
    "BisimHarness",
    "DiffReport",
    "KernelOracle",
    "MockOracle",
    "OracleAdapter",
    "Trace",
    "TraceEvent",
    "run_e2e_smoke",
]
