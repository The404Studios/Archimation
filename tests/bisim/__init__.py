"""
tests.bisim — empirical bisimulation harness for the Root of Authority kernel.

See ``README.md`` in this directory for the spec; roadmap anchor is
``docs/s75_roadmap.md`` §1.2.6 (Item 6 — Empirical bisim harness).

This package is importable on any host with a stdlib-only Python 3; the
full end-to-end RISC-V/Verilator path additionally requires Agent F's
kprobe syscall-tracer port (roadmap Item 8, ~240 LOC, currently deferred).

Sub-modules:
  * ``ape_pure_cross``       — pure-function cross-check against kernel
  * ``trace_harness``        — orchestrator + Oracle ABC
  * ``discrepancy_detector`` — diff two trace streams
  * ``test_bisim_smoke``     — pytest entry exercising all three
"""

__all__ = [
    "ape_pure_cross",
    "trace_harness",
    "discrepancy_detector",
]
