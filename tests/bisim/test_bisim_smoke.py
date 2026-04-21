"""End-to-end smoke test for the S75 empirical bisim harness.

Exercises:
  * APE pure-function cross-check (standalone — runs on any Python host)
  * Trace harness record/replay/diff round-trip
  * Discrepancy detector positive + negative tests

When ``/dev/trust`` is unavailable (WSL dev host), the kernel arm is
skipped cleanly with a documented reason — this is the expected state
until Agent F's RISC-V kprobe port and an ARCHIMATION-booted target
land (see roadmap §1.2.6 / §1.3.8).
"""
from __future__ import annotations

import pytest

import os
import sys
from pathlib import Path

# Allow `from ape_pure_cross import ...` when pytest discovers this file
# standalone (the tests/ tree has no __init__.py, so package-qualified
# imports aren't reliable across invocation styles).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from ape_pure_cross import (  # noqa: E402
    APE_CFG_PERM_COUNT,
    APE_CFG_TOTAL,
    PERM_TABLE,
    ApeHashCfg,
    apply_reconfigurable_hash_pure,
    cross_check,
    decode_cfg,
    generate_inputs,
)
from discrepancy_detector import DiscrepancyDetector  # noqa: E402
from trace_harness import (  # noqa: E402
    Action,
    BisimHarness,
    MockOracle,
    TraceEvent,
    run_e2e_smoke,
)


def test_perm_table_size_and_identity_first():
    """Heap's-algorithm table must have exactly 720 entries, first is identity."""
    assert len(PERM_TABLE) == APE_CFG_PERM_COUNT
    assert PERM_TABLE[0] == list(range(8))
    # All entries must be permutations of 0..7 (no duplicates).
    for row in PERM_TABLE:
        assert sorted(row) == list(range(8))


def test_apes_cfg_total_matches_paper():
    """Paper §APE claims 94,371,840 configurations — this BUILD_BUG_ONs in C."""
    assert APE_CFG_TOTAL == 94_371_840


def test_decode_cfg_zero_proof_is_identity():
    cfg = decode_cfg(bytes(32))
    assert cfg == ApeHashCfg(perm_idx=0, window=1, mask=0, rot=0)


def test_decode_cfg_known_vector():
    """Hand-computed: bytes 0x42, 0x7F, 0xA3, 0x11 → LE word 0x11A37F42.

    perm_idx = 0x42 % 720       = 66
    window   = 0x7F + 1         = 128
    mask     = 0xA3 & 0x0F      = 3
    rot      = (0x11A37F42 >> 20) & 0x1F = (0x11A) & 0x1F = 0x1A = 26
    """
    proof = bytes([0x42, 0x7F, 0xA3, 0x11]) + bytes(28)
    cfg = decode_cfg(proof)
    assert cfg == ApeHashCfg(perm_idx=66, window=128, mask=3, rot=26)


def test_apply_hash_zero_cfg_is_identity():
    """rot=0, mask=0, perm_idx=0 → all three steps degenerate to identity."""
    cfg = decode_cfg(bytes(32))
    data = bytes(range(64))
    out = apply_reconfigurable_hash_pure(data, cfg)
    assert out == data


def test_apply_hash_preserves_length():
    """Transform is length-preserving for all cfgs."""
    data = b"The quick brown fox jumps over the lazy dog!" + b"\x00" * 20
    for proof in generate_inputs(5):
        cfg_proof, _ = proof
        cfg = decode_cfg(cfg_proof)
        out = apply_reconfigurable_hash_pure(data, cfg)
        assert len(out) == len(data)


def test_ape_pure_cross_check_passes():
    """The 10-input pure cross-check runs and passes under the python-self oracle."""
    result = cross_check(count=10)
    assert result.ok, f"cross-check failed: {result.discrepancies}"
    assert result.oracle_mode in ("kernel-fixture", "python-self")
    assert result.passed >= 10


# --------------------------------------------------------------------- #
# Trace harness round-trip                                              #
# --------------------------------------------------------------------- #
def test_harness_record_and_replay_matched():
    """Two mocks with identical script produce bisimilar traces."""
    observed, expected, report = run_e2e_smoke()
    assert len(observed) == 3
    assert len(expected) == 3
    assert not report.has_divergence, report.summary


def test_harness_json_roundtrip():
    """Trace JSON → Trace → JSON must be stable."""
    observed, _, _ = run_e2e_smoke()
    s1 = observed.to_json()
    from trace_harness import Trace  # noqa: WPS433
    round_tripped = Trace.from_json(s1)
    s2 = round_tripped.to_json()
    assert s1 == s2


# --------------------------------------------------------------------- #
# Discrepancy detector positive + negative tests                        #
# --------------------------------------------------------------------- #
def _mk(op: str, result):
    return TraceEvent(ts=0.0, seq=0, actor="test", op=op, args=[], result=result)


def test_detector_negative_matched_traces_have_zero_discrepancies():
    """Matched traces → detector returns empty list."""
    a = [_mk("mint", "ab" * 4), _mk("consume", 0)]
    b = [_mk("mint", "ab" * 4), _mk("consume", 0)]
    detector = DiscrepancyDetector()
    assert detector.diff(a, b) == []


def test_detector_positive_byte_mismatch():
    """Fabricated byte-level mismatch → byte-mismatch category."""
    a = [_mk("mint", "ab" * 4)]
    b = [_mk("mint", "ac" * 4)]
    detector = DiscrepancyDetector()
    records = detector.diff(a, b)
    assert len(records) == 1
    assert records[0]["category"] == "byte-mismatch"
    assert records[0]["index"] == 0


def test_detector_positive_op_mismatch():
    a = [_mk("mint", 0)]
    b = [_mk("consume", 0)]
    detector = DiscrepancyDetector()
    records = detector.diff(a, b)
    assert len(records) == 1
    assert records[0]["category"] == "op-mismatch"


def test_detector_positive_length_mismatch():
    a = [_mk("mint", 0), _mk("consume", 1)]
    b = [_mk("mint", 0)]
    detector = DiscrepancyDetector()
    records = detector.diff(a, b)
    assert len(records) == 1
    assert records[0]["category"] == "length-mismatch"


def test_detector_positive_result_mismatch_non_bytelike():
    a = [_mk("status", {"state": "alive"})]
    b = [_mk("status", {"state": "dead"})]
    detector = DiscrepancyDetector()
    records = detector.diff(a, b)
    assert len(records) == 1
    assert records[0]["category"] == "result-mismatch"


# --------------------------------------------------------------------- #
# Kernel arm (skips on WSL dev host — expected)                         #
# --------------------------------------------------------------------- #
def test_kernel_oracle_skips_cleanly_without_libtrust(kernel_available):
    """On hosts without /dev/trust, KernelOracle.__init__ must fail cleanly."""
    if kernel_available:
        pytest.skip("/dev/trust present — kernel arm covered by integration tests")
    from trace_harness import KernelOracle  # noqa: WPS433
    with pytest.raises(OSError):
        KernelOracle()
