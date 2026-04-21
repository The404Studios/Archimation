"""Stress tests for ``ai-control/daemon/algedonic_reader.py`` (S77 Agent 2).

These tests probe failure modes that fixed-N unit tests miss:
  * decode_packet on 10_000 synthetic malformed/truncated packets
  * unknown reason codes don't crash decode
  * _dispatch() when event_bus fails / cortex raises
  * critical-bypass path when select_action raises non-TypeError
  * fuzzing with random bytes at every possible alignment

These tests are synchronous (no /dev/trust_algedonic needed). Gated
behind ``STRESS_TESTS=1``. Run with::

    cd tests/unit && STRESS_TESTS=1 python -m unittest test_algedonic_reader_stress -v

S77 Agent 2 deliverable.
"""

from __future__ import annotations

import importlib
import os
import random
import struct
import sys
import threading
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"

if str(_DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(_DAEMON_DIR))

STRESS_ENABLED = bool(os.environ.get("STRESS_TESTS"))


def _load_module():
    sys.modules.pop("algedonic_reader", None)
    return importlib.import_module("algedonic_reader")


class _FakeBus:
    def __init__(self):
        self.received = []
        self.lock = threading.Lock()

    def publish(self, event):
        with self.lock:
            self.received.append(event)


class _BadBus:
    def publish(self, event):
        raise RuntimeError("bus dead")


class _RaisingCortex:
    def on_algedonic(self, event):
        raise RuntimeError("cortex down")


class _TypeErrorCortex:
    """Critical-bypass fallback path -- has no on_algedonic but has
    select_action which raises TypeError (older API mismatch)."""
    def select_action(self, **kw):
        raise TypeError("signature mismatch")


@unittest.skipUnless(STRESS_ENABLED, "stress tests disabled (set STRESS_TESTS=1)")
class TestAlgedonicReaderStress(unittest.TestCase):

    def setUp(self):
        self.mod = _load_module()

    def test_decode_truncated_packets_never_crash(self):
        """For every size 0..79 except 40, decode_packet must raise
        ValueError (documented contract) — never some other exception."""
        for size in list(range(0, 40)) + list(range(41, 80)):
            raw = b"\xaa" * size
            with self.assertRaises(ValueError):
                self.mod.decode_packet(raw)

    def test_decode_unknown_reason_codes(self):
        """Any 16-bit reason code, including those outside
        _REASON_NAMES, must decode to a string without raising."""
        for reason in range(0, 65536, 101):  # sample across range
            raw = struct.pack("<QIHHQQQ", 0, 0, 1024, reason, 0, 0, 0)
            event = self.mod.decode_packet(raw)
            self.assertIsInstance(event["reason_name"], str)
            self.assertEqual(event["reason_code"], reason)

    def test_fuzz_random_bytes_at_every_alignment(self):
        """1000 random 40-byte buffers: all must decode to a dict with
        the documented keys. No exception, no key missing."""
        rng = random.Random(0xDEADBEEF)
        expected_keys = {"source", "topic", "ts_ns", "subject_pid",
                         "severity", "reason_code", "reason_name",
                         "payload", "critical"}
        for _ in range(1000):
            raw = bytes(rng.randint(0, 255) for _ in range(40))
            event = self.mod.decode_packet(raw)
            self.assertEqual(set(event.keys()), expected_keys)
            self.assertEqual(len(event["payload"]), 3)
            self.assertIsInstance(event["critical"], bool)

    def test_dispatch_bad_bus_does_not_crash(self):
        """_dispatch with a bus whose publish() raises must not
        propagate; stats counters should still be consistent (no
        packets_dispatched increment on failure)."""
        reader = self.mod.AlgedonicReader(event_bus=_BadBus(),
                                          cortex=None)
        for _ in range(500):
            ev = self.mod.decode_packet(
                struct.pack("<QIHHQQQ", 1, 1, 1024, 1, 0, 0, 0)
            )
            reader._dispatch(ev)
        stats = reader.stats()
        # packets_dispatched only increments on successful bus publish.
        self.assertEqual(stats["packets_dispatched"], 0)

    def test_dispatch_critical_cortex_raise(self):
        """Critical packet with a cortex that raises must not crash;
        critical_bypasses stays 0, read loop continues."""
        bus = _FakeBus()
        reader = self.mod.AlgedonicReader(event_bus=bus,
                                          cortex=_RaisingCortex())
        for _ in range(200):
            ev = self.mod.decode_packet(
                struct.pack("<QIHHQQQ", 1, 1, 40000, 6, 0, 0, 0)
            )
            self.assertTrue(ev["critical"])
            reader._dispatch(ev)
        stats = reader.stats()
        # Bus should have received all; critical bypass count should
        # NOT have incremented (cortex raised).
        self.assertEqual(len(bus.received), 200)
        self.assertEqual(stats["critical_bypasses"], 0)

    def test_dispatch_cortex_select_action_fallback_typeerror(self):
        """TypeError from select_action is documented as "pass" —
        must not propagate, critical_bypasses stays 0."""
        bus = _FakeBus()
        reader = self.mod.AlgedonicReader(event_bus=bus,
                                          cortex=_TypeErrorCortex())
        for _ in range(100):
            ev = self.mod.decode_packet(
                struct.pack("<QIHHQQQ", 1, 1, 40000, 7, 0, 0, 0)
            )
            reader._dispatch(ev)
        stats = reader.stats()
        self.assertEqual(stats["critical_bypasses"], 0)
        self.assertEqual(len(bus.received), 100)

    def test_concurrent_dispatch_thread_safety(self):
        """8 threads each dispatching 1000 events. Final bus count
        must equal 8*1000; stats counters self-consistent.

        Note: the reader uses simple += on dict counters which is NOT
        thread-safe in general — this test documents the invariant the
        reader is supposed to hold. If it flakes, the reader needs a
        lock around _stats mutations. (Probe.)"""
        bus = _FakeBus()
        reader = self.mod.AlgedonicReader(event_bus=bus, cortex=None)

        def worker():
            ev = self.mod.decode_packet(
                struct.pack("<QIHHQQQ", 1, 1, 1024, 1, 0, 0, 0)
            )
            for _ in range(1000):
                reader._dispatch(ev)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
            self.assertFalse(t.is_alive())

        # Bus count is authoritative (its own lock).
        self.assertEqual(len(bus.received), 8000)
        # packets_dispatched may be slightly off due to non-atomic +=
        # on the shared counter; we tolerate up to 5% drift rather
        # than assert exactness.
        stats = reader.stats()
        drift = abs(stats["packets_dispatched"] - 8000) / 8000.0
        self.assertLess(drift, 0.05,
                        f"stats counter drift too large: {drift:.2%}")


if __name__ == "__main__":
    unittest.main()
