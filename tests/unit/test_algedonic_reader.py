"""Unit tests for ``ai-control/daemon/algedonic_reader.py``.

Covers decode correctness, wire-format stability, and dispatcher
behaviour when a device is absent (WSL/QEMU build host). No live
``/dev/trust_algedonic`` is required -- we synthesize packets with
``struct.pack`` and verify round-trip.

S74 Integration / Research Finding #1.
"""

from __future__ import annotations

import asyncio
import importlib
import struct
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"

if str(_DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(_DAEMON_DIR))


def _load_module():
    sys.modules.pop("algedonic_reader", None)
    return importlib.import_module("algedonic_reader")


class _FakeBus:
    def __init__(self) -> None:
        self.received: list[dict] = []

    def publish(self, event: dict) -> None:
        self.received.append(event)


class _FakeCortex:
    def __init__(self) -> None:
        self.bypasses: list[dict] = []

    def on_algedonic(self, event: dict) -> None:
        self.bypasses.append(event)


def _pack(ts_ns: int, pid: int, sev: int, reason: int,
          d0: int = 0, d1: int = 0, d2: int = 0) -> bytes:
    return struct.pack("<QIHHQQQ", ts_ns, pid, sev, reason, d0, d1, d2)


class TestDecodePacket(unittest.TestCase):
    """Wire format and decode correctness."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_packet_size_is_40(self) -> None:
        # Platform sanity: the kernel emits __attribute__((packed))
        # 40-byte structs; any drift is an ABI break.
        self.assertEqual(struct.calcsize("<QIHHQQQ"), 40)

    def test_decode_roundtrip_minimal(self) -> None:
        raw = _pack(ts_ns=1_234_567_890, pid=0, sev=1024, reason=1)
        ev = self.mod.decode_packet(raw)
        self.assertEqual(ev["ts_ns"], 1_234_567_890)
        self.assertEqual(ev["subject_pid"], 0)
        self.assertEqual(ev["severity"], 1024)
        self.assertEqual(ev["reason_code"], 1)
        self.assertEqual(ev["reason_name"], "pool_exhaustion")
        self.assertEqual(ev["payload"], [0, 0, 0])
        self.assertFalse(ev["critical"])

    def test_decode_all_named_reasons(self) -> None:
        # Every reason code 1..9 must have a stable human-readable name
        # so cortex topic routing works.
        expected = {
            1: "pool_exhaustion",
            2: "ape_exhaustion",
            3: "cascade_apoptosis",
            4: "quorum_disputed_repeatedly",
            5: "morphogen_hot_spot",
            6: "cancer_detected",
            7: "tpm_drift",
            8: "proof_chain_break",
            9: "token_starvation_storm",
        }
        for code, name in expected.items():
            raw = _pack(1, 1234, 100, code)
            ev = self.mod.decode_packet(raw)
            self.assertEqual(ev["reason_name"], name, msg=f"reason {code}")
            self.assertEqual(ev["topic"], f"trust.algedonic.{name}")

    def test_decode_unknown_reason_is_safe(self) -> None:
        # Future kernel-side reason codes must not crash the decoder.
        raw = _pack(1, 1234, 100, 9999)
        ev = self.mod.decode_packet(raw)
        self.assertIn("unknown", ev["reason_name"])

    def test_decode_critical_flag(self) -> None:
        # SEVERITY_CRITICAL is 32768 -- strictly greater triggers fast-path.
        raw = _pack(1, 1234, 32768, 1)
        self.assertFalse(self.mod.decode_packet(raw)["critical"])
        raw = _pack(1, 1234, 32769, 1)
        self.assertTrue(self.mod.decode_packet(raw)["critical"])

    def test_decode_short_buffer_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.mod.decode_packet(b"\x00" * 10)


class TestReaderDispatch(unittest.TestCase):
    """Dispatcher wiring without touching a real device."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_dispatch_publishes_to_bus(self) -> None:
        bus = _FakeBus()
        reader = self.mod.AlgedonicReader(
            dev_path="/dev/definitely-does-not-exist",
            event_bus=bus,
        )
        ev = self.mod.decode_packet(_pack(1, 1234, 100, 1))
        reader._dispatch(ev)  # type: ignore[attr-defined]
        self.assertEqual(len(bus.received), 1)
        self.assertEqual(bus.received[0]["reason_name"], "pool_exhaustion")

    def test_dispatch_invokes_cortex_on_critical(self) -> None:
        bus = _FakeBus()
        cx = _FakeCortex()
        reader = self.mod.AlgedonicReader(
            dev_path="/dev/definitely-does-not-exist",
            event_bus=bus,
            cortex=cx,
        )
        critical_ev = self.mod.decode_packet(_pack(1, 1234, 40000, 6))
        reader._dispatch(critical_ev)  # type: ignore[attr-defined]
        self.assertEqual(len(cx.bypasses), 1)
        self.assertEqual(cx.bypasses[0]["reason_name"], "cancer_detected")

    def test_dispatch_skips_cortex_below_critical(self) -> None:
        bus = _FakeBus()
        cx = _FakeCortex()
        reader = self.mod.AlgedonicReader(
            dev_path="/dev/definitely-does-not-exist",
            event_bus=bus,
            cortex=cx,
        )
        warn_ev = self.mod.decode_packet(_pack(1, 1234, 16384, 1))
        reader._dispatch(warn_ev)  # type: ignore[attr-defined]
        self.assertEqual(len(cx.bypasses), 0)


class TestGracefulAbsentDevice(unittest.TestCase):
    """If ``/dev/trust_algedonic`` doesn't exist, start() is a no-op."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_start_logs_and_returns_if_absent(self) -> None:
        reader = self.mod.AlgedonicReader(
            dev_path="/dev/does-not-exist-for-testing-algedonic",
        )

        async def _run():
            await reader.start()
            # No task should have been created, no fd open
            self.assertIsNone(reader._task)
            self.assertEqual(reader._fd, -1)
            await reader.stop()

        asyncio.run(_run())


class TestWireUpHelper(unittest.TestCase):
    """register_with_daemon constructs a reader and is best-effort."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_register_returns_reader_with_stub_app(self) -> None:
        # A minimal stub app without .get() must not crash the helper.
        class _StubApp:
            pass

        reader = self.mod.register_with_daemon(
            _StubApp(), event_bus=_FakeBus()
        )
        self.assertIsInstance(reader, self.mod.AlgedonicReader)

    def test_register_returns_reader_with_none_app(self) -> None:
        reader = self.mod.register_with_daemon(None, event_bus=_FakeBus())
        self.assertIsInstance(reader, self.mod.AlgedonicReader)


if __name__ == "__main__":
    unittest.main()
